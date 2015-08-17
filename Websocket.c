#include "Websocket.h"
#include "Server.h"
#include "Base64.h"
#include "Global.h"
#include "IPv6Map.h"
#include "Logger.h"
#include <event2/bufferevent.h>
#include <openssl/sha.h>
#include <assert.h>
#include "Config.h"

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

static uint8_t *WebsocketConstructPacket(uint8_t Opcode, uint8_t *MaskingKey, bool Mask, uint8_t *Payload, uint32_t PayloadLen, OUT size_t *Length)
{
	uint8_t binBlock0 = 0;
	binBlock0 += (1 << 7) /* push FIN */ + Opcode;
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET CONSTRUCT opcode %x", Opcode);
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET CONSTRUCT binblock0 %x", binBlock0);
	HexDump("Payload", Payload, PayloadLen);
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
	} else {
		assert(false);
	}
	payloadOffset = Mask ? maskingKeyOffset + 4 : maskingKeyOffset;

	Log(LOG_LEVEL_DEBUG, "Websocket PACKET CONSTRUCT maskingKeyOffset %d", maskingKeyOffset);
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET CONSTRUCT payloadOffset %d", payloadOffset);

	uint8_t binBlock1 = len7;
	binBlock1 = Mask ? SET_BIT(binBlock1, 7) : CLEAR_BIT(binBlock1, 7);

	uint8_t *packet = malloc(payloadOffset + PayloadLen);
	packet[0] = binBlock0;
	packet[1] = binBlock1;
	if (len7 >= 126)
		*((uint16_t*)(&packet[2])) = len16;
	if (len7 == 127)
		*((uint32_t*)(&packet[6])) = len32;
	if (Mask)
		*((uint32_t*)(&packet[maskingKeyOffset])) = *((uint32_t*)MaskingKey);

	// TODO: fire up valgrind becaus eit seems that Payload[] is being corrupted at this point

	for (size_t x = 0; x < PayloadLen; x++) {
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET CONSTRUCT Payload[x] %c, XOR %c", Payload[x], (Payload[x] ^ (Mask ? MaskingKey[x % 4] : 0)));
		packet[payloadOffset + x] = Payload[x] ^ (Mask ? MaskingKey[x % 4] : 0);
	}

	HexDump("Payload 2", Payload, PayloadLen);

	HexDump("Websocket out payload", packet + payloadOffset, PayloadLen);

	*Length = payloadOffset + PayloadLen;
	return packet;
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
	HexDump("WebSocket", Buff, BuffLen);

	uint8_t opcode = (*Buff & 0xF); // get rid of 4 bits on left
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET opcode %d", opcode);
	if (!GET_BIT(Buff[1], 7)) {
		// Mask not set
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET mask not set");
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
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET lenEx %d", lenExtended);
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET len calc %d", ((Buff + BuffLen) - payload));
	if (lenExtended != ((Buff + BuffLen) - payload)) {
		// stop the ruse man
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET stopped ruse man");
		bufferevent_free(BuffEvent);
		return;
	}

	Log(LOG_LEVEL_DEBUG, "Websocket PACKET masking key %04x", *maskingKey);

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
				event_active(WebSocketUnfinishedPackets[foundIndex]->timeout, EV_TIMEOUT, 0);
				return;
			}

			WebSocketUnfinishedPackets[foundIndex]->dataLen += lenExtended;
			pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
				WebSocketUnfinishedPackets[foundIndex]->data = realloc(WebSocketUnfinishedPackets[foundIndex]->data,
																	   WebSocketUnfinishedPackets[foundIndex]->dataLen);
			} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);
			memcpy(WebSocketUnfinishedPackets[foundIndex]->data + lenExtended, payLoadDecoded, lenExtended);
			WebSocketUnfinishedPackets[foundIndex]->pieceCount++;
			Log(LOG_LEVEL_DEBUG, "Websocket PACKET extended unfinished packet");
		} else {
#ifdef DEBUG
			if (WebSocketUnfinishedPackets == NULL)
				assert(WebSocketUnfinishedPacketsSize == 0);
#endif
			pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
				WebSocketUnfinishedPackets = WebSocketUnfinishedPackets == NULL ?
					malloc(sizeof(*WebSocketUnfinishedPackets)) :
					realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * ++WebSocketUnfinishedPacketsSize);
			} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);
			WEB_SOCKET_UNFINISHED_PACKET *unfinishedPacket = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize - 1];
			unfinishedPacket = malloc(sizeof(WEB_SOCKET_UNFINISHED_PACKET));
			unfinishedPacket->data = payLoadDecoded;
			unfinishedPacket->dataLen = lenExtended;
			unfinishedPacket->pieceCount = 0;
			bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketTimeout, unfinishedPacket);
			Log(LOG_LEVEL_DEBUG, "Websocket PACKET registered unfinished packet");
		}
		return;
	}

	// Remove client unfinised packet struct
	pthread_mutex_lock(&WebSocketUnfinishedPacketsLock); {
		for (size_t x = 0;x < WebSocketUnfinishedPacketsSize;x++) {
			if (WebSocketUnfinishedPackets[x]->buffEvent == BuffEvent) {
				free(WebSocketUnfinishedPackets[x]->data);
				free(WebSocketUnfinishedPackets[x]);
				event_del(WebSocketUnfinishedPackets[x]->timeout);
				WebSocketUnfinishedPackets[x] = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize];
				WebSocketUnfinishedPackets = realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * --WebSocketUnfinishedPacketsSize);
				break;
			}
		}
	} pthread_mutex_unlock(&WebSocketUnfinishedPacketsLock);

	switch (opcode) {
		case WEBSOCKET_OPCODE_UNICODE: {
			Log(LOG_LEVEL_DEBUG, "Websocket PACKET payload %.*s", lenExtended, payLoadDecoded);

			/*


			TODO: Add 'cookie' auth


			*/

			WEBSOCKET_SERVER_NOTIFICATION_COMMANDS subscriptions = 0;

			/*if (lenExtended == 1 && *payLoadDecoded == WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES) {
				subscriptions = WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES;
			} else {
#ifdef DEBUG
				// Send go 2 hell
				size_t len;
				uint8_t *packet = WebsocketConstructPacket(WEBSOCKET_OPCODE_UNICODE, maskingKey, false, "go 2 hell", 9, &len); {
					Log(LOG_LEVEL_DEBUG, "Websocket PACKET sent go 2 hell");
					bufferevent_write(BuffEvent, packet, len);
				} free(packet);
#endif
				bufferevent_free(BuffEvent);
				return;
			}*/

			ssize_t foundIndex = -1;
			pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
				for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
					if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
						foundIndex = x;
						break;
					}
				}
			} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

			WEB_SOCKET_SUBSCRIBED_CLIENT *client;

			if (foundIndex != -1) {
				client = WebSocketSubscribedClients[foundIndex];
			} else {
				pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
					WebSocketSubscribedClientsSize++;

					WebSocketSubscribedClients = WebSocketSubscribedClients == NULL ?
						malloc(sizeof(*WebSocketSubscribedClients)) :
						realloc(WebSocketSubscribedClients, sizeof(*WebSocketSubscribedClients));
				} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);

				client = malloc(sizeof(WEB_SOCKET_UNFINISHED_PACKET));
				WebSocketSubscribedClients[WebSocketSubscribedClientsSize - 1] = client;

				client->buffEvent = BuffEvent;
				client->timer = event_new(bufferevent_get_base(BuffEvent), -1, EV_PERSIST, WebsocketClientPing, BuffEvent);

				struct timeval sec = { 1, 0 };
				event_add(client->timer, &sec);

				bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketClientTimeout, client);
			}

			client->subscriptions = subscriptions;
			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);

			break;
		}
		case WEBSOCKET_OPCODE_PING: {
			if (lenExtended > 125) {
				// nope
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET stopped ruse man");
				bufferevent_free(BuffEvent);
				return;
			}
			size_t len;
			uint8_t *packet = WebsocketConstructPacket(WEBSOCKET_OPCODE_PONG, maskingKey, false, payLoadDecoded, lenExtended, &len); {
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET PONG!");
				bufferevent_write(BuffEvent, packet, len);
			} free(packet);
			break;
		}
		case WEBSOCKET_OPCODE_PONG: {
			bool found = false;
			pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
				for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
					if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
						bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV); // reset timeouts
						found = true;
						break;
					}
				}
			} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
			assert(found);
			break;
		}
	}

	free(payLoadDecoded);
}

void WebsocketClientPing(evutil_socket_t fd, short Event, void *BuffEvent)
{
	Log(LOG_LEVEL_DEBUG, "Websocket CLIENT PING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	size_t len;
	uint8_t *packet = WebsocketConstructPacket(WEBSOCKET_OPCODE_PING, 0, false, "PING!", 5, &len); {
		Log(LOG_LEVEL_DEBUG, "Websocket PING!");
		bufferevent_write(BuffEvent, packet, len);
	} free(packet);
}

void WebsocketClientTimeout(struct bufferevent *BuffEvent, short Event, void *Ctx)
{
	Log(LOG_LEVEL_DEBUG, "Websocket client timeout ev %x!!!!!!!!!!!!!!!!!!!!!!!!!!!!", Event);
	WEB_SOCKET_SUBSCRIBED_CLIENT *client = (WEB_SOCKET_SUBSCRIBED_CLIENT*)Ctx;
	event_free(client->timer);
	free(client);
	pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
		client = WebSocketSubscribedClients[WebSocketSubscribedClientsSize];
		WebSocketSubscribedClients = realloc(WebSocketSubscribedClients, sizeof(*WebSocketSubscribedClients) * --WebSocketSubscribedClientsSize);
	} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
	bufferevent_free(BuffEvent);
}

void WebsocketTimeout(struct bufferevent *BuffEvent, short Event, void *Ctx)
{
	Log(LOG_LEVEL_DEBUG, "Websocket timeout ev %x!!!!!!!!!!!!!!!!!!!!!!!!!!!!", Event);
	if (Ctx != NULL) {
		WEB_SOCKET_UNFINISHED_PACKET *unfinishedPacket = (WEB_SOCKET_UNFINISHED_PACKET*)Ctx;
		free(unfinishedPacket->data);
		free(unfinishedPacket);
		event_del(unfinishedPacket->timeout);
		unfinishedPacket = WebSocketUnfinishedPackets[WebSocketUnfinishedPacketsSize];
		WebSocketUnfinishedPackets = realloc(WebSocketUnfinishedPackets, sizeof(*WebSocketUnfinishedPackets) * --WebSocketUnfinishedPacketsSize);
	}
	bufferevent_free(BuffEvent);
}

const char *WEB_SOCKET_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void WebsocketSwitch(struct bufferevent *BuffEvent, char *Buff)
{
	Log(LOG_LEVEL_DEBUG, "Websocket SWITCH");
	char *key;
	if (!ServerFindHeader("Sec-WebSocket-Key: ", Buff, &key, NULL, NULL)) {
		Log(LOG_LEVEL_DEBUG, "Websocket no sec key");
		bufferevent_write(BuffEvent, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request", 59 * sizeof(char));
		return;
	}

	char *concated[((strlen(key) + strlen(WEB_SOCKET_MAGIC)) * sizeof(char)) + 1];
	strcpy(concated, key);
	strcat(concated, WEB_SOCKET_MAGIC);
	concated[((strlen(key) + strlen(WEB_SOCKET_MAGIC)) * sizeof(char))] = 0x00;

	Log(LOG_LEVEL_DEBUG, "Websocket CAT %s", concated);

	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(concated, strlen(concated), hash); // that was easy

	char *b64;
	Base64Encode(hash, SHA_DIGEST_LENGTH, &b64); {
		Log(LOG_LEVEL_DEBUG, "Websocket SHA %s", b64);
		bufferevent_write(BuffEvent, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ", 97 * sizeof(char));
		bufferevent_write(BuffEvent, b64, strlen(b64) * sizeof(char));
		bufferevent_write(BuffEvent, "\r\n\r\n", 4 * sizeof(char));
	} free(b64);
	Log(LOG_LEVEL_DEBUG, "Websocket switched protocols");
	bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketTimeout, NULL);
	bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
}