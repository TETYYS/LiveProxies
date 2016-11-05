#include "Websocket.h"
#include "Server.h"
#include "Base64.h"
#include "Global.h"
#include "Logger.h"
#include <event2/bufferevent.h>
#include <openssl/sha.h>
#include "Config.h"
#include "Interface.h"
#include "ProxyLists.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static void HexDump(char *desc, void *addr, int len)
{
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

static size_t WebsocketPacketLen(bool Mask, uint32_t PayloadLen)
{
	size_t maskingKeyOffset;
	size_t payloadOffset;
	if (PayloadLen < UINT16_MAX)
		maskingKeyOffset = 2;
	else if (PayloadLen >= UINT8_MAX && PayloadLen < UINT16_MAX)
		maskingKeyOffset = 4;
	else if (PayloadLen >= UINT16_MAX)
		maskingKeyOffset = 6;
	
	payloadOffset = Mask ? maskingKeyOffset + 4 : maskingKeyOffset;
	return payloadOffset + PayloadLen;
}

static void WebsocketConstructPacket(uint8_t Opcode, uint8_t *MaskingKey, bool Mask, uint8_t *Payload, uint32_t PayloadLen, OUT uint8_t *Packet)
{
	Packet[0] = Opcode;
	Packet[0] = SET_BIT(Packet[0], 7); // Set FIN
	uint8_t len7 = 0;
	uint16_t len16 = 0;
	uint32_t len32 = 0;
	size_t maskingKeyOffset;
	size_t payloadOffset;
	if (PayloadLen < UINT16_MAX) {
		len7 = PayloadLen;
		len16 = 0;
		len32 = 0;
		maskingKeyOffset = 2;
	} else if (PayloadLen >= UINT8_MAX && PayloadLen < UINT16_MAX) {
		len7 = 126;
		len16 = PayloadLen;
		len32 = 0;
		maskingKeyOffset = 4;
	} else if (PayloadLen >= UINT16_MAX) {
		len7 = 127;
		len16 = 0;
		len32 = PayloadLen;
		maskingKeyOffset = 6;
	} else
		assert(false);
	payloadOffset = Mask ? maskingKeyOffset + 4 : maskingKeyOffset;

	Packet[1] = len7;
	Packet[1] = Mask ? SET_BIT(Packet[1], 7) : CLEAR_BIT(Packet[1], 7);

	if (len7 >= 126)
		*((uint16_t*)(&Packet[2])) = len16;
	if (len7 == 127)
		*((uint32_t*)(&Packet[6])) = len32;
	if (Mask) {
		*((uint32_t*)(&Packet[maskingKeyOffset])) = *((uint32_t*)MaskingKey);
		
		for (size_t x = 0; x < PayloadLen; x++)
			Packet[payloadOffset + x] = Payload[x] ^ MaskingKey[x % 4];
	} else
		memcpy((void*)((size_t)Packet + payloadOffset), Payload, PayloadLen);
	
	HexDump("Constructed packet", Packet, PayloadLen + payloadOffset);
}

void WebsocketClientsNotifySingle(struct bufferevent *BuffEvent, void *Message, size_t MessageLen, uint32_t Command)
{
	uint32_t cmd = htonl(Command);
	uint8_t packet[WebsocketPacketLen(false, sizeof(cmd) + MessageLen)];
	uint8_t payload[4 + MessageLen];
	memcpy(payload, &cmd, sizeof(cmd));
	memcpy((void*)((size_t)payload + sizeof(cmd)), Message, MessageLen) ;

	WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, 0, false, payload, sizeof(cmd) + MessageLen, packet);
	bufferevent_write(BuffEvent, packet, sizeof(packet));

	Log(LOG_LEVEL_DEBUG, "Client notify sent");
}

void WebsocketClientsNotify(void *Message, size_t MessageLen, uint32_t Command, bool ForceSend)
{
	uint32_t cmd = htonl(Command);
	pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
		for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
			if ((WebSocketSubscribedClients[x]->subscriptions & Command) != Command)
				continue;
			
			WEB_SOCKET_MESSAGE_INTERVAL *msgInterval = NULL;
			for (size_t i = 0;i < WebSocketSubscribedClients[x]->lastMessagesSize;i++) {
				if (WebSocketSubscribedClients[x]->lastMessages[i].subscription != Command)
					continue;
				
				if (WebSocketSubscribedClients[x]->lastMessages[i].lastMessageMs + WSMessageInterval > GetUnixTimestampMilliseconds()
					&& (Command == WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES || Command == WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES)
					&& !ForceSend) {
					pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
					return;
				}
				msgInterval = &(WebSocketSubscribedClients[x]->lastMessages[i]);
			}
			
			if (msgInterval == NULL) {
				Log(LOG_LEVEL_ERROR, "msgInterval NULL");
				pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
				assert(false);
				return;
			}
			
			uint8_t packet[WebsocketPacketLen(false, sizeof(cmd) + MessageLen)];
			uint8_t payload[4 + MessageLen];
			memcpy(payload, &cmd, sizeof(cmd));
			memcpy((void*)((size_t)payload + sizeof(cmd)), Message, MessageLen) ;

			WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, 0, false, payload, sizeof(cmd) + MessageLen, packet);
			bufferevent_write(WebSocketSubscribedClients[x]->buffEvent, packet, sizeof(packet));
			msgInterval->lastMessageMs = GetUnixTimestampMilliseconds();
			Log(LOG_LEVEL_DEBUG, "Client notify sent");
		}
	} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
}

void WebsocketLanding(struct bufferevent *BuffEvent, uint8_t *Buff, uint64_t BuffLen)
{
	/*
	0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-------+-+-------------+-------------------------------+
	|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	|N|V|V|V|       |S|             |   (if payload len==126/127)   |
	| |1|2|3|       |K|             |                               |
	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	|     Extended payload length continued, if payload len == 127  |
	+ - - - - - - - - - - - - - - - +-------------------------------+
	|                               |Masking-key, if MASK set to 1  |
	+-------------------------------+-------------------------------+
	| Masking-key (continued)       |          Payload Data         |
	+-------------------------------- - - - - - - - - - - - - - - - +
	:                     Payload Data continued ...                :
	+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	|                     Payload Data continued ...                |
	+---------------------------------------------------------------+
	*/

	//HexDump("WebSocket", Buff, BuffLen);

	uint8_t opcode = (*Buff & 0xF); // get rid of 4 bits on left
	
	if (!GET_BIT(Buff[1], 7)) {
		// Mask not set
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET mask not set");

		pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
			for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
				if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
					pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
					WebsocketClientTimeout(BuffEvent, EV_TIMEOUT, WebSocketSubscribedClients[x]);
					return;
				}
			}
		} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

		bufferevent_free(BuffEvent);
		return;
	}

	uint8_t *maskingKey;
	uint8_t *payload;

	uint8_t binBlock2 = *((uint8_t*)(&Buff[1]));
	uint8_t len = CLEAR_BIT(binBlock2, 7);
	uint64_t lenExtended;
	if (len == 126) {
		// switch to 16
		lenExtended = ntohs(*((uint16_t*)(&Buff[2])));
		maskingKey = (uint8_t*)(&Buff[4]);
		payload = (uint8_t*)(&Buff[8]);
	} else if (len == 127) {
		uint64_t binBlock5through7 = htobe64(*((uint64_t*)(&Buff[2])));
		lenExtended = binBlock5through7;
		maskingKey = (uint8_t*)(&Buff[10]);
		payload = (uint8_t*)(&Buff[14]);
	} else {
		lenExtended = len;
		maskingKey = (uint8_t*)(&Buff[2]);
		payload = (uint8_t*)(&Buff[6]);
	}

	
	if (lenExtended > ((Buff + BuffLen) - payload)) {
		// stop the ruse man
		pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
			for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
				if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
					pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
					WebsocketClientTimeout(BuffEvent, EV_TIMEOUT, WebSocketSubscribedClients[x]);
					return;
				}
			}
		} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

		bufferevent_free(BuffEvent);
		return;
	}

#if DEBUG
	if (lenExtended != ((Buff + BuffLen) - payload))
		Log(LOG_LEVEL_WARNING, "Websocket payload lengths do not match");
#endif

	uint8_t *payLoadDecoded = malloc(lenExtended);
	for (uint32_t x = 0; x < lenExtended; x++)
		payLoadDecoded[x] = payload[x] ^ maskingKey[x % 4];

	if (!GET_BIT(*Buff, 7)) {
		ssize_t foundIndex = -1;
		pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
			for (size_t x = 0;x < WebSocketUnfinishedPacketsSize;x++) {
				if (WebSocketUnfinishedPackets[x]->buffEvent == BuffEvent) {
					foundIndex = x;
					Log(LOG_LEVEL_DEBUG, "Websocket PACKET found unfinished packet");
					break;
				}
			}
		} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);

		if (foundIndex != -1) {
			if (WebSocketUnfinishedPackets[foundIndex]->pieceCount > WEB_SOCKETS_MAX_PIECE_COUNT) {
				// Ok, that's enough, you're out
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET stopped ruse man");
				event_active(WebSocketUnfinishedPackets[foundIndex]->timeout, EV_TIMEOUT, 0); // stop the ruse man
				goto end;
			}

			WebSocketUnfinishedPackets[foundIndex]->dataLen += lenExtended;
			WebSocketUnfinishedPackets[foundIndex]->data = realloc(WebSocketUnfinishedPackets[foundIndex]->data,
																   WebSocketUnfinishedPackets[foundIndex]->dataLen);
			memcpy(WebSocketUnfinishedPackets[foundIndex]->data + lenExtended, payLoadDecoded, lenExtended);
			WebSocketUnfinishedPackets[foundIndex]->pieceCount++;
			Log(LOG_LEVEL_DEBUG, "Websocket PACKET extended unfinished packet");
		} else {
#ifdef DEBUG
			if (WebSocketUnfinishedPackets == NULL)
				if (WebSocketUnfinishedPacketsSize != 0) {
					Log(LOG_LEVEL_ERROR, "WebSocketUnfinishedPacketsSize != 0");
				}
#endif
			pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
				WebSocketUnfinishedPacketsSize++;

				WebSocketUnfinishedPackets = WebSocketUnfinishedPackets == NULL ?
					malloc(sizeof(*WebSocketUnfinishedPackets)) :
					realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * WebSocketUnfinishedPacketsSize);
			} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);
			WEB_SOCKET_UNFINISHED_PACKET *unfinishedPacket = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize - 1];
			unfinishedPacket = malloc(sizeof(WEB_SOCKET_UNFINISHED_PACKET));
			unfinishedPacket->data = payLoadDecoded;
			unfinishedPacket->dataLen = lenExtended;
			unfinishedPacket->pieceCount = 0;
			bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketUnfinishedPacketTimeout, unfinishedPacket);
			Log(LOG_LEVEL_DEBUG, "Websocket PACKET registered unfinished packet");

		}
		
		goto end;
	}

	// Remove client unfinished packet struct
	pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
		for (size_t x = 0;x < WebSocketUnfinishedPacketsSize;x++) {
			if (WebSocketUnfinishedPackets[x]->buffEvent == BuffEvent) {
				free(WebSocketUnfinishedPackets[x]->data);
				free(WebSocketUnfinishedPackets[x]);
				event_del(WebSocketUnfinishedPackets[x]->timeout);

				WebSocketUnfinishedPacketsSize--;
				if (WebSocketUnfinishedPacketsSize > 0)
					WebSocketUnfinishedPackets[x] = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize];
				WebSocketUnfinishedPackets = realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * WebSocketUnfinishedPacketsSize);
				break;
			}
		}
	} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);
	// After this, no freeing is required at further opcode processing

	HexDump("Binary payload", payLoadDecoded, lenExtended);
	switch (opcode) {

		case WEBSOCKET_OPCODE_UNICODE:
		case WEBSOCKET_OPCODE_BINARY: {
			ssize_t foundIndex = -1;
			pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
				for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
					if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
						foundIndex = x;
						break;
					}
				}
			} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

			if (foundIndex != -1) {
				// Already authed
				Log(LOG_LEVEL_DEBUG, "Already authed");

				goto end;
			} else {
				bool authed = false;
				pthread_mutex_lock(&AuthWebLock); {
					for (size_t x = 0;x < AuthWebCount;x++) {
						if ((size_t)(lenExtended - sizeof(uint32_t)) == strlen((char*)AuthWebList[x]->rndVerify) &&
							strncmp((const char*)AuthWebList[x]->rndVerify,
								(const char*)(payLoadDecoded + sizeof(uint32_t)),
								(size_t)(lenExtended - sizeof(uint32_t))) == 0) {
							authed = true;
							break;
						}
					}
				} pthread_mutex_unlock(&AuthWebLock);
				if (!authed) {
					// Wrong 'password'
					Log(LOG_LEVEL_DEBUG, "Key mismatch");
					size_t packetLen = WebsocketPacketLen(false, 1);
					uint8_t *packet = malloc(packetLen); {
						WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, NULL, false, (uint8_t*)"\x00", 1, packet);
						bufferevent_write(BuffEvent, packet, packetLen);
					} free(packet);

					bufferevent_free(BuffEvent); // this is actually ruse man, so stop him
					goto end;
				} else {
					// Welcome
					Log(LOG_LEVEL_DEBUG, "AUTHED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
					size_t packetLen = WebsocketPacketLen(false, 1);
					uint8_t packet[packetLen];
					WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, NULL, false, (uint8_t*)"\x01", 1, packet);
					bufferevent_write(BuffEvent, packet, packetLen);
				}
			}

			// Register client
			pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
				WebSocketSubscribedClientsSize++;

				WebSocketSubscribedClients = WebSocketSubscribedClients == NULL ?
					malloc(sizeof(*WebSocketSubscribedClients)) :
					realloc(WebSocketSubscribedClients, sizeof(*WebSocketSubscribedClients) * WebSocketSubscribedClientsSize);
			} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

			WEB_SOCKET_SUBSCRIBED_CLIENT *client = malloc(sizeof(WEB_SOCKET_UNFINISHED_PACKET));
			WebSocketSubscribedClients[WebSocketSubscribedClientsSize - 1] = client;

			client->buffEvent = BuffEvent;
			client->timer = event_new(bufferevent_get_base(BuffEvent), -1, EV_PERSIST, WebsocketClientPing, BuffEvent);
			if (*(uint32_t*)payLoadDecoded > (WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES + WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES + WEBSOCKET_SERVER_COMMAND_PROXY_ADD + WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE + WEBSOCKET_SERVER_COMMAND_UPROXY_ADD + WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE)) {
				// Ruse man!!
				WebsocketClientTimeout(BuffEvent, EV_TIMEOUT, client);
				goto end;
			}

			client->subscriptions = *(uint32_t*)payLoadDecoded;
			client->lastMessagesSize = 0;
			client->lastMessages = NULL;
			for (size_t x = 0; x < WEBSOCKET_TOTAL_SERVER_COMMANDS;x++) {
				if (((1 << x) & client->subscriptions) == (1 << x)) {
					client->lastMessagesSize++;
					client->lastMessages = client->lastMessages == NULL ? malloc(sizeof(WEB_SOCKET_MESSAGE_INTERVAL)) : realloc(client->lastMessages, sizeof(WEB_SOCKET_MESSAGE_INTERVAL) * client->lastMessagesSize);
					client->lastMessages[client->lastMessagesSize - 1].lastMessageMs = 0;
					client->lastMessages[client->lastMessagesSize - 1].subscription = (1 << x);
				}
			}

			struct timeval tv = { WSPingInterval / 1000, (WSPingInterval % 1000) * 1000 };
			event_add(client->timer, &tv);

			bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketClientTimeout, client);
			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);

			break;
		}
		case WEBSOCKET_OPCODE_PING: {
			if (lenExtended > 125) {
				// nope
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET stopped ruse man");
				bufferevent_free(BuffEvent);
				goto end;
			}
			size_t packetLen = WebsocketPacketLen(false, lenExtended);
			uint8_t *packet = malloc(packetLen); {
				WebsocketConstructPacket(WEBSOCKET_OPCODE_PONG, NULL, false, payLoadDecoded, lenExtended, packet);
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET PONG!");
				bufferevent_write(BuffEvent, packet, packetLen);
			} free(packet);
			break;
		}
		case WEBSOCKET_OPCODE_PONG: {
			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV); // reset timeouts
			break;
		}
	}

end:
	free(payLoadDecoded);
}

void WebsocketClientPing(evutil_socket_t fd, short Event, void *BuffEvent)
{
	size_t packetLen = WebsocketPacketLen(false, 5);
	uint8_t *packet = malloc(packetLen); {
		WebsocketConstructPacket(WEBSOCKET_OPCODE_PING, 0, false, (uint8_t*)"PING!", 5, packet);
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET PING!");
		bufferevent_write(BuffEvent, packet, packetLen);
	} free(packet);
}

void WebsocketClientTimeout(struct bufferevent *BuffEvent, short Event, void *Ctx)
{
	Log(LOG_LEVEL_DEBUG, "Websocket client timeout ev %x!!!!!!!!!!!!!!!!!!!!!!!!!!!!", Event);
	WEB_SOCKET_SUBSCRIBED_CLIENT *client = (WEB_SOCKET_SUBSCRIBED_CLIENT*)Ctx;
	event_free(client->timer);
	free(client);
	pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
		WebSocketSubscribedClientsSize--;
		if (WebSocketSubscribedClientsSize > 0) {
			for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
				if (WebSocketSubscribedClients[x] == client) {
					WebSocketSubscribedClients[x] = WebSocketSubscribedClients[WebSocketSubscribedClientsSize];
				}
			}
		}
		WebSocketSubscribedClients = realloc(WebSocketSubscribedClients, sizeof(*WebSocketSubscribedClients) * WebSocketSubscribedClientsSize);
	} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
	bufferevent_free(BuffEvent);
}

void WebsocketUnfinishedPacketTimeout(struct bufferevent *BuffEvent, short Event, void *Ctx)
{
	Log(LOG_LEVEL_DEBUG, "Websocket timeout ev %x!!!!!!!!!!!!!!!!!!!!!!!!!!!!", Event);
	if (Ctx != NULL) {
		WEB_SOCKET_UNFINISHED_PACKET *unfinishedPacket = (WEB_SOCKET_UNFINISHED_PACKET*)Ctx;
		free(unfinishedPacket->data);
		free(unfinishedPacket);
		event_del(unfinishedPacket->timeout);

		pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
			WebSocketUnfinishedPacketsSize--;
			if (WebSocketUnfinishedPacketsSize > 0) {
				for (size_t x = 0;x < WebSocketUnfinishedPacketsSize;x++) {
					if (WebSocketUnfinishedPackets[x] == unfinishedPacket) {
						WebSocketUnfinishedPackets[x] = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize];
						break;
					}
				}
			}
			WebSocketUnfinishedPackets = realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * WebSocketUnfinishedPacketsSize);
		} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);
	}
	bufferevent_free(BuffEvent);
}

const char *WEB_SOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void WebsocketSwitch(struct bufferevent *BuffEvent, char *Buff)
{
	Log(LOG_LEVEL_DEBUG, "Websocket SWITCH");
	char *key;
	if (!HTTPFindHeader("Sec-WebSocket-Key: ", Buff, &key, NULL, NULL)) {
		Log(LOG_LEVEL_DEBUG, "Websocket no sec key");
		bufferevent_write(BuffEvent, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request", 59);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	char concated[strlen(key) + strlen(WEB_SOCKET_MAGIC) + 1];
	strcpy(concated, (const char*)key);
	strcat(concated, WEB_SOCKET_MAGIC);
	concated[strlen(key) + strlen(WEB_SOCKET_MAGIC)] = 0x00;
	free(key);

	Log(LOG_LEVEL_DEBUG, "Websocket CAT %s", concated);

	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char*)concated, strlen(concated), hash); // that was easy

	char *b64;
	Base64Encode(hash, SHA_DIGEST_LENGTH, &b64); {
		Log(LOG_LEVEL_DEBUG, "Websocket SHA %s", b64);
		bufferevent_write(BuffEvent, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ", 97);
		bufferevent_write(BuffEvent, b64, strlen(b64));
		bufferevent_write(BuffEvent, "\r\n\r\n", 4);
	} free(b64);
	Log(LOG_LEVEL_DEBUG, "Websocket switched protocols");
	bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketUnfinishedPacketTimeout, NULL);
	bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
}