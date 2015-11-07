#include "Websocket.h"
#include "Server.h"
#include "Base64.h"
#include "Global.h"
#include "IPv6Map.h"
#include "Logger.h"
#include <event2/bufferevent.h>
#include <openssl/sha.h>
#include "Config.h"
#include "Interface.h"
#include "ProxyLists.h"
#include "HtmlTemplate.h"
#include "PortableEndian.h"

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
	}
	payloadOffset = Mask ? maskingKeyOffset + 4 : maskingKeyOffset;
	return payloadOffset + PayloadLen;
}

static void WebsocketConstructPacket(uint8_t Opcode, uint8_t *MaskingKey, bool Mask, uint8_t *Payload, uint32_t PayloadLen, OUT uint8_t *Packet)
{
	uint8_t binBlock0 = 0;
	binBlock0 += (1 << 7) /* push FIN */ + Opcode;
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
	}
	payloadOffset = Mask ? maskingKeyOffset + 4 : maskingKeyOffset;

	uint8_t binBlock1 = len7;
	binBlock1 = Mask ? SET_BIT(binBlock1, 7) : CLEAR_BIT(binBlock1, 7);

	Log(LOG_LEVEL_DEBUG, "binBlock0 %x", binBlock0);

	Packet[0] = binBlock0;
	Packet[1] = binBlock1;
	if (len7 >= 126)
		*((uint16_t*)(&Packet[2])) = len16;
	if (len7 == 127)
		*((uint32_t*)(&Packet[6])) = len32;
	if (Mask)
		*((uint32_t*)(&Packet[maskingKeyOffset])) = *((uint32_t*)MaskingKey);

	for (size_t x = 0; x < PayloadLen; x++) {
		Packet[payloadOffset + x] = Payload[x] ^ (Mask ? MaskingKey[x % 4] : 0);
	}
}

void WebsocketClientsNotifySingle(struct bufferevent *BuffEvent, void *Message, size_t MessageLen, uint32_t Command)
{
	if (HtmlTemplateUseStock)
		return;

	uint32_t cmd = htonl(Command);
	uint8_t *packet = malloc(WebsocketPacketLen(false, sizeof(cmd) + MessageLen)); {
		uint8_t *payload = malloc(4 + MessageLen); {
			memcpy(payload, &cmd, sizeof(cmd));
			memcpy(payload + sizeof(cmd), Message, MessageLen);

			WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, 0, false, payload, sizeof(cmd) + MessageLen, packet);
		} free(payload);
		bufferevent_write(BuffEvent, packet, sizeof(packet));
	} free(packet);

	Log(LOG_LEVEL_DEBUG, "Client notify sent");
}

void WebsocketClientsNotify(void *Message, size_t MessageLen, uint32_t Command)
{
	if (HtmlTemplateUseStock)
		return;

	uint32_t cmd = htonl(Command);
	pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
		for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
			if ((WebSocketSubscribedClients[x]->subscriptions & Command) == Command) {
				WEB_SOCKET_MESSAGE_INTERVAL *msgInterval;
				for (size_t i = 0;i < WebSocketSubscribedClients[x]->lastMessagesSize;i++) {
					if (WebSocketSubscribedClients[x]->lastMessages[i].subscription == Command) {
						if (WebSocketSubscribedClients[x]->lastMessages[i].lastMessageMs + WSMessageIntervalMs > GetUnixTimestampMilliseconds()
							&& Command != WEBSOCKET_SERVER_COMMAND_PROXY_ADD && Command != WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE
							&& Command != WEBSOCKET_SERVER_COMMAND_UPROXY_ADD && Command != WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE) {
							pthread_mutex_unlock(&WebSocketSubscribedClientsLock);
							return;
						} else
							msgInterval = &(WebSocketSubscribedClients[x]->lastMessages[i]);
					}
				}
				uint8_t *packet = malloc(WebsocketPacketLen(false, sizeof(cmd) + MessageLen)); {
					uint8_t *payload = malloc(4 + MessageLen); {
						memcpy(payload, &cmd, sizeof(cmd));
						memcpy(payload + sizeof(cmd), Message, MessageLen);

						WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, 0, false, payload, sizeof(cmd) + MessageLen, packet);
					} free(payload);
					bufferevent_write(WebSocketSubscribedClients[x]->buffEvent, packet, sizeof(packet));
				} free(packet);
				msgInterval->lastMessageMs = GetUnixTimestampMilliseconds();
				Log(LOG_LEVEL_DEBUG, "Client notify sent");
			}
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

	HexDump("WebSocket", Buff, BuffLen);

	uint8_t opcode = (*Buff & 0xF); // get rid of 4 bits on left
	Log(LOG_LEVEL_DEBUG, "Websocket PACKET opcode %d", opcode);
	if (!GET_BIT(Buff[1], 7)) {
		// Mask not set
		Log(LOG_LEVEL_DEBUG, "Websocket PACKET mask not set");

		pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
			for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
				if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
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

	Log(LOG_LEVEL_DEBUG, "Actual length: %d, sent length: %d", ((Buff + BuffLen) - payload), lenExtended);
	if (lenExtended > ((Buff + BuffLen) - payload)) {
		// stop the ruse man
		pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
			for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
				if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {
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
				return;
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
		return;
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

			AUTH_WEB *authWeb;

			if (foundIndex != -1) {
				// Already authed
				Log(LOG_LEVEL_DEBUG, "Already authed");

				// Pull data on demand
				if (*payLoadDecoded == 'P') {
					uint32_t sub = *(uint32_t*)(payLoadDecoded + 1);
					switch (sub) {
						case WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES:
						case WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES: {
							if (lenExtended < 1 + sizeof(uint32_t) + sizeof(uint64_t)) {
								Log(LOG_LEVEL_DEBUG, "Ruse man on pull data on demand");
								WebsocketClientTimeout(BuffEvent, EV_TIMEOUT, WebSocketSubscribedClients[foundIndex]); // ruse man
								goto end;
							}
							uint64_t val = *(uint64_t*)(payLoadDecoded + 1 + sizeof(uint32_t));
							uint64_t target = sub == WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES ? SizeCheckedProxies : SizeUncheckedProxies;

							if (val != target) {
								uint64_t network = htobe64(target);
								Log(LOG_LEVEL_DEBUG, "Sent on pull data on demand");
								WebsocketClientsNotifySingle(BuffEvent, &network, sizeof(network), sub);
							} else {
								Log(LOG_LEVEL_DEBUG, "Sent on pull data on demand [SAME]");
							}
							break;
						}
					}
				}

				free(payLoadDecoded);
				return;
			} else {
				bool authed = false;
				pthread_mutex_lock(&AuthWebLock); {
					for (size_t x = 0;x < AuthWebCount;x++) {
						if (lenExtended - sizeof(uint32_t) == strlen(AuthWebList[x]->rndVerify) && strncmp(AuthWebList[x]->rndVerify, payLoadDecoded + sizeof(uint32_t), lenExtended - sizeof(uint32_t)) == 0) {
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
						WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, maskingKey, false, "\x00", 1, packet);
						bufferevent_write(BuffEvent, packet, packetLen);
					} free(packet);

					bufferevent_free(BuffEvent); // this is actually ruse man, so stop him
					goto end;
				} else {
					// Welcome
					Log(LOG_LEVEL_DEBUG, "AUTHED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
					size_t packetLen = WebsocketPacketLen(false, 1);
					uint8_t *packet = malloc(packetLen); {
						WebsocketConstructPacket(WEBSOCKET_OPCODE_BINARY, maskingKey, false, "\x01", 1, packet);
						bufferevent_write(BuffEvent, packet, packetLen);
					} free(packet);
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
			if (*(uint32_t*)payLoadDecoded > (WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES + WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES + WEBSOCKET_SERVER_COMMAND_PROXY_ADD + WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE +
											  WEBSOCKET_SERVER_COMMAND_UPROXY_ADD + WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE)) {
				// Ruse man!!
				WebsocketClientTimeout(BuffEvent, EV_TIMEOUT, client);
				goto end;
				return;
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

			struct timeval sec = { GlobalTimeoutTV.tv_sec / 2, GlobalTimeoutTV.tv_usec / 2 };
			event_add(client->timer, &sec);

			bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketClientTimeout, client);


			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);

			break;
		}
		case WEBSOCKET_OPCODE_PING: {
			if (lenExtended > 125) {
				// nope
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET stopped ruse man");
				bufferevent_free(BuffEvent);
				free(payLoadDecoded);
				return;
			}
			size_t packetLen = WebsocketPacketLen(false, lenExtended);
			uint8_t *packet = malloc(packetLen); {
				WebsocketConstructPacket(WEBSOCKET_OPCODE_PONG, maskingKey, false, payLoadDecoded, lenExtended, packet);
				Log(LOG_LEVEL_DEBUG, "Websocket PACKET PONG!");
				bufferevent_write(BuffEvent, packet, packetLen);
			} free(packet);
			break;
		}
		case WEBSOCKET_OPCODE_PONG: {
			/*pthread_mutex_lock(&WebSocketSubscribedClientsLock); {
				for (size_t x = 0;x < WebSocketSubscribedClientsSize;x++) {
					if (WebSocketSubscribedClients[x]->buffEvent == BuffEvent) {*/
			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV); // reset timeouts
			/*break;
		}
	}
} pthread_mutex_unlock(&WebSocketSubscribedClientsLock);*/
			break;
		}
	}

end:
	free(payLoadDecoded);
}

void WebsocketClientPing(evutil_socket_t fd, short Event, void *BuffEvent)
{
	Log(LOG_LEVEL_DEBUG, "Websocket CLIENT PING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! LEN %d", WebsocketPacketLen(false, 5 * sizeof(char)));
	size_t packetLen = WebsocketPacketLen(false, 5 * sizeof(char));
	uint8_t *packet = malloc(packetLen); {
		WebsocketConstructPacket(WEBSOCKET_OPCODE_PING, 0, false, "PING!", 5 * sizeof(char), packet);
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
		bufferevent_write(BuffEvent, "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request", 59 * sizeof(char));
		return;
	}

	char *concated = malloc(((strlen(key) + strlen(WEB_SOCKET_MAGIC)) * sizeof(char)) + 1); {
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
	} free(concated);
	Log(LOG_LEVEL_DEBUG, "Websocket switched protocols");
	bufferevent_setcb(BuffEvent, ServerRead, NULL, WebsocketUnfinishedPacketTimeout, NULL);
	bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
}