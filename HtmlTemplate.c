#include "HtmlTemplate.h"
#include "Logger.h"
#include <dirent.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "Global.h"
#include "ProxyLists.h"
#include "Interface.h"
#include "IPv6Map.h"
#include <libconfig.h>
#include <event2/buffer.h>
#include <assert.h>
#include "Base64.h"
#include "Harvester.h"

char *HtmlTemplateTags[] = {	"{T_VERSION}",						"{T_CURRENT_PAGE}",				"{T_CFG_HOME_ACTIVE}",			"{T_CFG_UPROXIES_ACTIVE}",		"{T_CFG_PROXIES_ACTIVE}",	"{T_CFG_SOURCES_ACTIVE}",
								"{T_CFG_STATS_ACTIVE}",				"{T_USER}",						"{T_COUNT_UPROXIES}",			"{T_COUNT_PROXIES}",			"{T_UPROXIES_HEAD}",		"{T_UPROXIES_TABLE_ITEMS_START}",
								"{T_UPROXIES_TABLE_ITEMS_END}",		"{T_CFG_TABLE_ODD}",			"{T_CFG_TABLE_EVEN}",			"{T_CFG_TABLE_OK}",				"{T_CFG_TABLE_WARN}",		"{T_CFG_TABLE_ERR}",
								"{T_UPROXIES_ITEM}",				"{T_PROXIES_HEAD}",				"{T_PROXIES_TABLE_ITEMS_START}","{T_PROXIES_TABLE_ITEMS_END}",	"{T_PROXIES_ITEM}",			"{T_PRXSRC_HEAD}",
								"{T_PRXSRC_TABLE_ITEMS_START}",		"{T_PRXSRC_TABLE_ITEMS_END}",	"{T_PRXSRC_ITEM}",				NULL,							"{T_TABLE_BREAK}",			"{T_STATS_GEO_HEAD}",
								"{T_STATS_GEO_TABLE_ITEMS_START}",	"{T_STATS_GEO_TABLE_ITEMS_END}","{T_STATS_GEO_ITEM}",			"{T_CHECK_IP}",					"{T_CHECK_PORT}",			"{T_CHECK_TYPE}",
								"{T_CHECK_COUNTRY_LOWER}",			"{T_CHECK_COUNTRY_UPPER}",		"{T_CHECK_LIVE_SINCE}",			"{T_CHECK_LAST_CHECKED}",		"{T_CHECK_CONNECT_TIMEOUT}","{T_CHECK_HTTP_S_TIMEOUT}",
								"{T_CHECK_SUCCESSFUL_CHECKS}",		"{T_CHECK_FAILED_CHECKS}",		"{T_CHECK_RETRIES}",			"{T_CHECK_UID}"
};

static char *StrReplace(char *string, char *substr, char *replacement)
{
	char *tok = NULL;
	char *newstr = NULL;
	char *oldstr = NULL;

	if (substr == NULL || replacement == NULL)
		return strdup(string);
	newstr = strdup(string);
	while ((tok = strstr(newstr, substr))) {
		oldstr = newstr;
		newstr = malloc(strlen(oldstr) - strlen(substr) + strlen(replacement) + 1);

		if (newstr == NULL) {
			free(oldstr);
			return NULL;
		}
		memcpy(newstr, oldstr, tok - oldstr);
		memcpy(newstr + (tok - oldstr), replacement, strlen(replacement));
		memcpy(newstr + (tok - oldstr) + strlen(replacement), tok + strlen(substr), strlen(oldstr) - strlen(substr) - (tok - oldstr));
		memset(newstr + strlen(oldstr) - strlen(substr) + strlen(replacement), 0, 1);
		free(oldstr);
	}
	return newstr;
}

void HtmlTemplateLoadAll()
{
	HtmlTemplateUseStock = false;

	DIR *d;
	struct dirent *dir;
	uint8_t itemsFound = 0;
	bool fullPath = false;

	d = opendir("./html");
	if (!d) {
		d = opendir("/etc/liveproxies/html");
		fullPath = true;
	}

	char *files[] = { "head.tmpl", "foot.tmpl", "home.tmpl", "iface.tmpl", "ifaceu.tmpl", "prxsrc.tmpl", "stats.tmpl", "check.tmpl" };

	if (d) {
		config_t cfg;
		config_init(&cfg);

		if (config_read_file(&cfg, "html/html.conf") == CONFIG_FALSE) {
			Log(LOG_LEVEL_DEBUG, "Failed to open html/html.conf in working directory, opening in global...: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));

			if (config_read_file(&cfg, "/etc/liveproxies/html/html.conf") == CONFIG_FALSE) {
				Log(LOG_LEVEL_ERROR, "Failed to open /etc/liveproxies/html/html.conf: %s (line %d), using stock HTML...", config_error_text(&cfg), config_error_line(&cfg));
				HtmlTemplateUseStock = true;
				return;
			}
		}

		config_setting_t *cfgRoot = config_root_setting(&cfg);

		while ((dir = readdir(d)) != NULL) {
			for (size_t x = 0;x < arrlen(files);x++) {
				if (strcmp(dir->d_name, files[x]) == 0) {
					Log(LOG_LEVEL_DEBUG, "Found %s", files[x]);
					char name[(strlen(dir->d_name) + (fullPath ? 21 : 6) * sizeof(char)) + 1];
					sprintf(name, "%s/%s", fullPath ? "/etc/liveproxies/html" : "./html", files[x]);
					FILE *hFile = fopen(name, "r");
					if (hFile != NULL) {
						Log(LOG_LEVEL_DEBUG, "Parsing %s...", dir->d_name);

						if (strcmp(dir->d_name, "head.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateHead, &HtmlTemplateHeadSize, cfgRoot);
						if (strcmp(dir->d_name, "foot.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateFoot, &HtmlTemplateFootSize, cfgRoot);
						if (strcmp(dir->d_name, "home.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateHome, &HtmlTemplateHomeSize, cfgRoot);
						if (strcmp(dir->d_name, "iface.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateProxies, &HtmlTemplateProxiesSize, cfgRoot);
						if (strcmp(dir->d_name, "ifaceu.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateUProxies, &HtmlTemplateUProxiesSize, cfgRoot);
						if (strcmp(dir->d_name, "prxsrc.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateProxySources, &HtmlTemplateProxySourcesSize, cfgRoot);
						if (strcmp(dir->d_name, "stats.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateStats, &HtmlTemplateStatsSize, cfgRoot);
						if (strcmp(dir->d_name, "check.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateCheck, &HtmlTemplateCheckSize, cfgRoot);

						itemsFound++;
					}
				}
			}
		}

		//config_destroy(&cfg);

		if (itemsFound != 8) {
			Log(LOG_LEVEL_ERROR, "Not all HTML templates found, using stock HTML...");
			HtmlTemplateUseStock = true;
		}

		closedir(d);
		Log(LOG_LEVEL_DEBUG, "Parsed all HTML tempalates");
	} else {
		Log(LOG_LEVEL_ERROR, "Cannot open HTML template dir, using stock HTML...");
		HtmlTemplateUseStock = true;
		return;
	}
}

void HtmlTemplateMimeTypesInit()
{
	if (HtmlTemplateUseStock)
		return;

	config_t cfg;
	config_init(&cfg);
	HtmlTemplateMimeTypes = NULL;
	HtmlTemplateMimeTypesSize = 0;

	if (config_read_file(&cfg, "html/html.conf") == CONFIG_FALSE) {
		Log(LOG_LEVEL_DEBUG, "Failed to open html/html.conf in working directory, opening in global...: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));

		if (config_read_file(&cfg, "/etc/liveproxies/html/html.conf") == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to open /etc/liveproxies/html/html.conf: %s (line %d), using stock HTML...", config_error_text(&cfg), config_error_line(&cfg));
			HtmlTemplateUseStock = true;
			return;
		}
	}

	config_setting_t *cfgRoot = config_root_setting(&cfg);

	size_t x = 0;
	config_setting_t *currentBlock;

	config_setting_t *mimeTypes = config_setting_get_member(cfgRoot, "MimeTypes");
	if (mimeTypes != NULL) {
		while ((currentBlock = config_setting_get_elem(mimeTypes, x)) != NULL) {
			char *val = config_setting_get_string(currentBlock);
			if (x % 2 == 0) {
				if (HtmlTemplateMimeTypes == NULL)
					HtmlTemplateMimeTypes = malloc(++HtmlTemplateMimeTypesSize * sizeof(HTML_TEMPLATE_MIME_TYPE));
				else
					HtmlTemplateMimeTypes = realloc(HtmlTemplateMimeTypes, ++HtmlTemplateMimeTypesSize * sizeof(HTML_TEMPLATE_MIME_TYPE));

				HtmlTemplateMimeTypes[HtmlTemplateMimeTypesSize - 1].extension = malloc((strlen(val) * sizeof(char)) + 1);
				strcpy(HtmlTemplateMimeTypes[HtmlTemplateMimeTypesSize - 1].extension, val);
			} else {
				HtmlTemplateMimeTypes[HtmlTemplateMimeTypesSize - 1].type = malloc((strlen(val) * sizeof(char)) + 1);
				strcpy(HtmlTemplateMimeTypes[HtmlTemplateMimeTypesSize - 1].type, config_setting_get_string(currentBlock));
			}
			x++;
		}
	}
	config_destroy(&cfg);
}

static void HtmlTemplateFindFirst(char *Contents, OUT HTML_TEMPLATE_COMPONENT_IDENTIFIER *Identifier, OUT char **Offset)
{
	*Offset = SIZE_MAX;
	*Identifier = HTML_TEMPLATE_COMPONENT_IDENTIFIER_INVALID;

	for (size_t x = 0;x < arrlen(HtmlTemplateTags);x++) {
		if (HtmlTemplateTags[x] == NULL)
			continue;

		char *cur = strstr(Contents, HtmlTemplateTags[x]);
		if (cur != NULL && cur < *Offset) {
			*Offset = cur;
			*Identifier = x;
		}
	}
	if (*Identifier != HTML_TEMPLATE_COMPONENT_IDENTIFIER_INVALID)
		Log(LOG_LEVEL_DEBUG, "HtmlTemplateFindFirst: %d", *Identifier);
	else
		Log(LOG_LEVEL_DEBUG, "HtmlTemplateFindFirst: NULL");
}

static void HtmlTemplateComponentPush(HTML_TEMPLATE_COMPONENT **Components, size_t *CurrentSize, HTML_TEMPLATE_COMPONENT Component)
{
	(*CurrentSize)++;

	*Components = *CurrentSize == 1 ? malloc(*CurrentSize * sizeof(HTML_TEMPLATE_COMPONENT)) : realloc(*Components, *CurrentSize * sizeof(HTML_TEMPLATE_COMPONENT));
	memcpy(&((*Components)[*CurrentSize - 1]), &Component, sizeof(HTML_TEMPLATE_COMPONENT));
}

void HtmlTemplateParse(FILE *hFile, HTML_TEMPLATE_COMPONENT **Template, size_t *SizeRef, config_setting_t *CfgRoot)
{
	fseek(hFile, 0, SEEK_END);
	size_t size = ftell(hFile);
	fseek(hFile, 0, SEEK_SET);

	char string[size + 1];
	fread(string, size, 1, hFile);
	fclose(hFile);
	string[size] = 0;

	*SizeRef = 0;
	*Template = NULL;

	char *curEnd = string;

	HTML_TEMPLATE_COMPONENT_IDENTIFIER identifier;
	HTML_TEMPLATE_COMPONENT comp;
	char *offset;

	while (1) {
		Log(LOG_LEVEL_DEBUG, "Finding first...");
		HtmlTemplateFindFirst(curEnd, &identifier, &offset);

		if (identifier == HTML_TEMPLATE_COMPONENT_IDENTIFIER_INVALID) {
			Log(LOG_LEVEL_DEBUG, "No more components");
			// No more components
			comp.identifier = HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATIC;
			comp.content = malloc((strlen(curEnd) * sizeof(char)) + 1);
			strcpy(comp.content, curEnd);
			HtmlTemplateComponentPush(Template, SizeRef, comp);
			break;
		} else {
			if (offset != curEnd) {
				Log(LOG_LEVEL_DEBUG, "Pushing static content...");
				// Push static content in front of component
				comp.identifier = HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATIC;
				comp.content = malloc(offset - curEnd + 1);
				strncpy(comp.content, curEnd, offset - curEnd);
				((char*)(comp.content))[offset - curEnd] = 0x00;

				Log(LOG_LEVEL_DEBUG, "Static content: %s", comp.content);

				HtmlTemplateComponentPush(Template, SizeRef, comp);
				curEnd = offset;
			}
			if (offset == curEnd) {
				Log(LOG_LEVEL_DEBUG, "Pushing dynamic content...");
				// Push dynamic content
				comp.identifier = identifier;

#define CONFIG_STRING(cfg, svar, var) const char *val; if (config_setting_lookup_string(cfg, svar, &val) == CONFIG_FALSE) { Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %s...", svar); HtmlTemplateUseStock = true; return; } else { var = malloc((strlen(val) * sizeof(char)) + 1); strcpy(var, val); }

				switch (identifier) {
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_VERSION: {
						comp.content = VERSION;
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_HOME_ACTIVE: {
						CONFIG_STRING(CfgRoot, "HomeActive", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_UPROXIES_ACTIVE: {
						CONFIG_STRING(CfgRoot, "UProxiesActive", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_PROXIES_ACTIVE: {
						CONFIG_STRING(CfgRoot, "ProxiesActive", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_SOURCES_ACTIVE: {
						CONFIG_STRING(CfgRoot, "SourcesActive", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_STATS_ACTIVE: {
						CONFIG_STRING(CfgRoot, "StatsActive", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ODD: {
						CONFIG_STRING(CfgRoot, "TableOdd", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_EVEN: {
						CONFIG_STRING(CfgRoot, "TableEven", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_OK: {
						CONFIG_STRING(CfgRoot, "TableOk", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_WARN: {
						CONFIG_STRING(CfgRoot, "TableWarn", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ERR: {
						CONFIG_STRING(CfgRoot, "TableError", comp.content);
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_COUNT_PROXIES: {
						comp.content = &SizeCheckedProxies;
						break;
					}
					case HTML_TEMPLATE_COMPONENT_IDENTIFIER_COUNT_UPROXIES: {
						comp.content = &SizeUncheckedProxies;
						break;
					}
				}

#undef CONFIG_STRING
				HtmlTemplateComponentPush(Template, SizeRef, comp);
				curEnd = offset + strlen(HtmlTemplateTags[identifier]);
			}
		}
		Log(LOG_LEVEL_DEBUG, "Size: %d", *SizeRef);
	}
}

void HtmlTemplateBufferInsert(struct evbuffer *Buffer, HTML_TEMPLATE_COMPONENT *Components, size_t Size, INTERFACE_INFO Info, HTML_TEMPALTE_TABLE_INFO TableInfo)
{
	uint8_t rowStatus = 0;

	if (TableInfo.inTable) {
		switch (Info.currentPage->page) {
			case INTERFACE_PAGE_UPROXIES: {
				// No color
				rowStatus = 0;
				break;
			}
			case INTERFACE_PAGE_PROXIES: {
				// Switch on anonymity
				switch (((PROXY*)(TableInfo.tableObject))->anonymity) {
					case ANONYMITY_MAX: {
						rowStatus = 1;
						break;
					}
					case ANONYMITY_ANONYMOUS: {
						rowStatus = 2;
						break;
					}
					case ANONYMITY_TRANSPARENT: {
						rowStatus = 3;
						break;
					}
				}
				break;
			}
		}
	}

	if (Info.currentPage->page == INTERFACE_PAGE_CHECK)
		assert(TableInfo.tableObject != NULL);

	Log(LOG_LEVEL_DEBUG, "TableInfo:");
	Log(LOG_LEVEL_DEBUG, ".x: %d", TableInfo.currentComponentIteration);
	Log(LOG_LEVEL_DEBUG, ".inTable: %s", TableInfo.inTable ? "true" : "false");
	Log(LOG_LEVEL_DEBUG, ".iteration: %d", TableInfo.tableObjectIteration);
	Log(LOG_LEVEL_DEBUG, ".tableObject: %p", TableInfo.tableObject);

	Log(LOG_LEVEL_DEBUG, "Size: %d", Size);

	for (size_t x = TableInfo.currentComponentIteration;x < Size;x++) {
		Log(LOG_LEVEL_DEBUG, "Component (%d): ", x);
		Log(LOG_LEVEL_DEBUG, ".content: %s", Components[x].content);
		Log(LOG_LEVEL_DEBUG, ".identifier: %d", Components[x].identifier);

		switch (Components[x].identifier) {
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CURRENT_PAGE: {
				evbuffer_add_reference(Buffer, Info.currentPage->name, strlen(Info.currentPage->name), NULL, NULL);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_HOME_ACTIVE: {
				if (Info.currentPage->page != INTERFACE_PAGE_HOME)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_UPROXIES_ACTIVE: {
				if (Info.currentPage->page != INTERFACE_PAGE_UPROXIES)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_PROXIES_ACTIVE: {
				if (Info.currentPage->page != INTERFACE_PAGE_PROXIES)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_SOURCES_ACTIVE: {
				if (Info.currentPage->page != INTERFACE_PAGE_PRXSRC)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_STATS_ACTIVE: {
				if (Info.currentPage->page != INTERFACE_PAGE_STATS)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ODD: {
				if (!TableInfo.inTable || TableInfo.tableObjectIteration % 2 == 0)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_EVEN: {
				if (!TableInfo.inTable || TableInfo.tableObjectIteration % 2 != 0)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_OK: {
				if (!TableInfo.inTable || rowStatus != 1)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_WARN: {
				if (!TableInfo.inTable || rowStatus != 2)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ERR: {
				if (!TableInfo.inTable || rowStatus != 3)
					continue;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_USER: {
				evbuffer_add_reference(Buffer, Info.user, strlen(Info.user), NULL, NULL);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_COUNT_UPROXIES:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_COUNT_PROXIES: {
				evbuffer_add_printf(Buffer, "%d", *((size_t*)(Components[x].content)));
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_HEAD:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_ITEM: {
				bool item = Components[x].identifier == HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_ITEM;
				UNCHECKED_PROXY *uproxy = (UNCHECKED_PROXY*)TableInfo.tableObject;

				switch (TableInfo.tableHeadOrItemIteration) {
					case 0: {
						if (item) {
							char *ip = IPv6MapToString2(uproxy->ip); {
								evbuffer_add_printf(Buffer, "%s:%d", ip, uproxy->port);
							} free(ip);
						} else
							evbuffer_add_reference(Buffer, "IP:Port", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 1: {
						if (item)
							evbuffer_add_printf(Buffer, "%s", ProxyGetTypeString(uproxy->type));
						else
							evbuffer_add_reference(Buffer, "Type", 4 * sizeof(char), NULL, NULL);
						break;
					}
					case 2: {
						if (item)
							evbuffer_add_reference(Buffer, uproxy->checking ? "check" : "x", (uproxy->checking ? 5 : 1) * sizeof(char), NULL, NULL);
						else
							evbuffer_add_reference(Buffer, "Currently checking", 18 * sizeof(char), NULL, NULL);
						break;
					}
					case 3: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", uproxy->retries);
						else
							evbuffer_add_reference(Buffer, "Retries", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 4: {
						if (item)
							evbuffer_add_reference(Buffer, uproxy->associatedProxy != NULL ? "check" : "x", (uproxy->associatedProxy != NULL ? 5 : 1) * sizeof(char), NULL, NULL);
						else
							evbuffer_add_reference(Buffer, "Rechecking", 10 * sizeof(char), NULL, NULL);
						TableInfo.tableHeadOrItemIteration = -1; // line+4 sets it to 0
						break;
					}
				}
				TableInfo.tableHeadOrItemIteration++; // << line+4
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_HEAD:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_ITEM: {
				bool item = Components[x].identifier == HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_ITEM;
				PROXY *proxy = (PROXY*)TableInfo.tableObject;

				switch (TableInfo.tableHeadOrItemIteration) {
					case 0: {
						if (item) {
							char *ip = IPv6MapToString2(proxy->ip); {
								evbuffer_add_printf(Buffer, "%s:%d", ip, proxy->port);
							} free(ip);
						} else
							evbuffer_add_reference(Buffer, "IP:Port", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 1: {
						if (item)
							evbuffer_add_printf(Buffer, "%s", ProxyGetTypeString(proxy->type));
						else
							evbuffer_add_reference(Buffer, "Type", 4 * sizeof(char), NULL, NULL);
						break;
					}
					case 2: {
						if (item)
							evbuffer_add_reference(Buffer, proxy->country, 2 * sizeof(char), NULL, NULL);
						else
							evbuffer_add_reference(Buffer, "Country", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 3: {
						if (item) {
							if (proxy->anonymity == ANONYMITY_MAX)
								evbuffer_add_reference(Buffer, "Max", 3 * sizeof(char), NULL, NULL);
							else if (proxy->anonymity == ANONYMITY_ANONYMOUS)
								evbuffer_add_reference(Buffer, "Anonymous", 9 * sizeof(char), NULL, NULL);
							else if (proxy->anonymity == ANONYMITY_TRANSPARENT)
								evbuffer_add_reference(Buffer, "Transparent", 11 * sizeof(char), NULL, NULL);
							else
								evbuffer_add_reference(Buffer, "N/A", 3 * sizeof(char), NULL, NULL);
						} else
							evbuffer_add_reference(Buffer, "Anonymity", 9 * sizeof(char), NULL, NULL);
						break;
					}
					case 4: {
						if (item) {
							evbuffer_add_printf(Buffer, "%d", proxy->timeoutMs);
						} else
							evbuffer_add_reference(Buffer, "Connection latency (ms)", 23 * sizeof(char), NULL, NULL);
						break;
					}
					case 5: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", proxy->httpTimeoutMs);
						else
							evbuffer_add_reference(Buffer, "HTTP/S latency (ms)", 19 * sizeof(char), NULL, NULL);
						break;
					}
					case 6: {
						if (item) {
							char *time = FormatTime(proxy->liveSinceMs); {
								evbuffer_add_printf(Buffer, "%s", time);
							} free(time);
						} else
							evbuffer_add_reference(Buffer, "Live since", 10 * sizeof(char), NULL, NULL);
						break;
					}
					case 7: {
						if (item) {
							char *time = FormatTime(proxy->lastCheckedMs); {
								evbuffer_add_printf(Buffer, "%s", time);
							} free(time);
						} else
							evbuffer_add_reference(Buffer, "Last checked", 12 * sizeof(char), NULL, NULL);
						break;
					}
					case 8: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", proxy->retries);
						else
							evbuffer_add_reference(Buffer, "Retries", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 9: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", proxy->successfulChecks);
						else
							evbuffer_add_reference(Buffer, "Successful checks", 17 * sizeof(char), NULL, NULL);
						break;
					}
					case 10: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", proxy->failedChecks);
						else
							evbuffer_add_reference(Buffer, "Failed checks", 13 * sizeof(char), NULL, NULL);
						break;
					}
					case 11: {
						if (item) {
							char *uid = GenerateUidForProxy(proxy); {
								evbuffer_add_printf(Buffer, "<a href=\"/recheck?uid=%s\">Check</a>", uid);
							} free(uid);
						} else
							evbuffer_add_reference(Buffer, "Full check", 10 * sizeof(char), NULL, NULL);
						TableInfo.tableHeadOrItemIteration = -1; // line+4 sets it to 0
						break;
					}
				}
				TableInfo.tableHeadOrItemIteration++; // << line+4
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_HEAD:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_ITEM: {
				bool item = Components[x].identifier == HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_ITEM;
				HARVESTER_PRXSRC_STATS_ENTRY *entry = (HARVESTER_PRXSRC_STATS_ENTRY*)TableInfo.tableObject;

				switch (TableInfo.tableHeadOrItemIteration) {
					case 0: {
						if (item) {
							evbuffer_add_reference(Buffer, entry->name, strlen(entry->name) * sizeof(char), NULL, NULL);
						} else
							evbuffer_add_reference(Buffer, "Name", 4 * sizeof(char), NULL, NULL);
						break;
					}
					case 1: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", entry->addedNew);
						else
							evbuffer_add_reference(Buffer, "New proxies", 11 * sizeof(char), NULL, NULL);
						break;
					}
					case 2: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", entry->added);
						else
							evbuffer_add_reference(Buffer, "Total proxies", 13 * sizeof(char), NULL, NULL);
						TableInfo.tableHeadOrItemIteration = -1; // line+4 sets it to 0
						break;
					}
				}
				TableInfo.tableHeadOrItemIteration++; // << line+4
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_HEAD:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_ITEM: {
				bool item = Components[x].identifier == HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_ITEM;
				HTML_TEMPLATE_TABLE_STATS_GEO *entry = (HTML_TEMPLATE_TABLE_STATS_GEO*)TableInfo.tableObject;

				switch (TableInfo.tableHeadOrItemIteration) {
					case 0: {
						if (item) {
							evbuffer_add_reference(Buffer, entry->countryCode, 2 * sizeof(char), NULL, NULL);
						} else
							evbuffer_add_reference(Buffer, "Country", 7 * sizeof(char), NULL, NULL);
						break;
					}
					case 1: {
						if (item)
							evbuffer_add_printf(Buffer, "%d", entry->count);
						else
							evbuffer_add_reference(Buffer, "Proxies", 7 * sizeof(char), NULL, NULL);
						TableInfo.tableHeadOrItemIteration = -1; // line+4 sets it to 0
						break;
					}
				}
				TableInfo.tableHeadOrItemIteration++; // << line+4
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_TABLE_ITEMS_START: {
				pthread_mutex_lock(&LockUncheckedProxies); {
					for (size_t i = 0;i < SizeUncheckedProxies;i++) {
						HTML_TEMPALTE_TABLE_INFO tableInfo;
						tableInfo.inTable = true;
						tableInfo.currentComponentIteration = x + 1;
						tableInfo.tableObjectIteration = i;
						tableInfo.tableHeadOrItemIteration = 0;
						tableInfo.tableObject = UncheckedProxies[i];
						HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
					}
				} pthread_mutex_unlock(&LockUncheckedProxies);
				while (Components[x].identifier != HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_TABLE_ITEMS_END || x > Size)
					x++;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_TABLE_ITEMS_START: {
				pthread_mutex_lock(&LockCheckedProxies); {
					for (size_t i = 0;i < SizeCheckedProxies;i++) {
						HTML_TEMPALTE_TABLE_INFO tableInfo;
						tableInfo.inTable = true;
						tableInfo.currentComponentIteration = x + 1;
						tableInfo.tableObjectIteration = i;
						tableInfo.tableHeadOrItemIteration = 0;
						tableInfo.tableObject = CheckedProxies[i];
						HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
					}
				} pthread_mutex_unlock(&LockCheckedProxies);
				while (Components[x].identifier != HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_TABLE_ITEMS_END || x > Size)
					x++;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_TABLE_ITEMS_START: {
				pthread_mutex_lock(&LockHarvesterPrxsrcStats); {
					for (size_t i = 0;i < SizeHarvesterPrxsrcStats;i++) {
						HTML_TEMPALTE_TABLE_INFO tableInfo;
						tableInfo.inTable = true;
						tableInfo.currentComponentIteration = x + 1;
						tableInfo.tableObjectIteration = i;
						tableInfo.tableHeadOrItemIteration = 0;
						tableInfo.tableObject = &(HarvesterPrxsrcStats[i]);
						HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
					}
				} pthread_mutex_unlock(&LockHarvesterPrxsrcStats);
				while (Components[x].identifier != HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_TABLE_ITEMS_END || x > Size)
					x++;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_TABLE_ITEMS_START: {
				HTML_TEMPLATE_TABLE_STATS_GEO *statsGeo = NULL;
				size_t statsGeoSize = 0;
				pthread_mutex_lock(&LockCheckedProxies); {
					for (size_t i = 0;i < SizeCheckedProxies;i++) {
						ssize_t foundIndex = -1;
						for (size_t a = 0;a < statsGeoSize;a++) {
							if (strncmp(statsGeo[a].countryCode, CheckedProxies[i]->country, 2 * sizeof(char)) == 0) {
								foundIndex = a;
								break;
							}
						}
						if (foundIndex != -1) {
							statsGeo[foundIndex].count++;
						} else {
							statsGeo = statsGeoSize == 0 ? malloc(++statsGeoSize * sizeof(HTML_TEMPLATE_TABLE_STATS_GEO)) : realloc(statsGeo, ++statsGeoSize * sizeof(HTML_TEMPLATE_TABLE_STATS_GEO));
							statsGeo[statsGeoSize - 1].countryCode = CheckedProxies[i]->country;
							statsGeo[statsGeoSize - 1].count = 1;
						}
					}
				} pthread_mutex_unlock(&LockCheckedProxies);
				for (size_t i = 0;i < statsGeoSize;i++) {
					HTML_TEMPALTE_TABLE_INFO tableInfo;
					tableInfo.inTable = true;
					tableInfo.currentComponentIteration = x + 1;
					tableInfo.tableObjectIteration = i;
					tableInfo.tableHeadOrItemIteration = 0;
					tableInfo.tableObject = &(statsGeo[i]);
					HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
				}
				free(statsGeo);
				while (Components[x].identifier != HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_TABLE_ITEMS_END || x > Size)
					x++;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_IP: {
				char *ip = IPv6MapToString2(((PROXY*)(TableInfo.tableObject))->ip); {
					evbuffer_add_printf(Buffer, "%s", ip);
				} free(ip);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_TYPE: {
				evbuffer_add_printf(Buffer, "%s", ProxyGetTypeString(((PROXY*)(TableInfo.tableObject))->type));
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_COUNTRY_LOWER: {
				PROXY *proxy = (PROXY*)(TableInfo.tableObject);
				evbuffer_add_printf(Buffer, "%c%c", tolower(proxy->country[0]), tolower(proxy->country[1]));
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_COUNTRY_UPPER: {
				evbuffer_add_printf(Buffer, "%s", ((PROXY*)(TableInfo.tableObject))->country);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_LIVE_SINCE: {
				char *time = FormatTime(((PROXY*)(TableInfo.tableObject))->liveSinceMs); {
					evbuffer_add_printf(Buffer, "%s", time);
				} free(time);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_LAST_CHECKED: {
				char *time = FormatTime(((PROXY*)(TableInfo.tableObject))->lastCheckedMs); {
					evbuffer_add_printf(Buffer, "%s", time);
				} free(time);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_UID: {
				char *uid = GenerateUidForProxy((PROXY*)(TableInfo.tableObject)); {
					evbuffer_add_printf(Buffer, "%s", uid);
				} free(uid);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_PORT: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->port);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_CONNECT_TIMEOUT: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->timeoutMs);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_HTTP_S_TIMEOUT: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->httpTimeoutMs);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_SUCCESSFUL_CHECKS: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->successfulChecks);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_FAILED_CHECKS: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->failedChecks);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CHECK_RETRIES: {
				evbuffer_add_printf(Buffer, "%d", ((PROXY*)(TableInfo.tableObject))->retries);
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_UPROXIES_TABLE_ITEMS_END:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PROXIES_TABLE_ITEMS_END:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_PRXSRC_TABLE_ITEMS_END:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATS_GEO_TABLE_ITEMS_END: {
				return;
				break;
			}
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_TABLE_BREAK: {
				TableInfo.tableHeadOrItemIteration = 0;
				break;
			}
		}
		switch (Components[x].identifier) {
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_STATIC:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_VERSION:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_HOME_ACTIVE:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_UPROXIES_ACTIVE:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_PROXIES_ACTIVE:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_SOURCES_ACTIVE:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_STATS_ACTIVE:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ODD:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_EVEN:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_OK:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_WARN:
			case HTML_TEMPLATE_COMPONENT_IDENTIFIER_CFG_TABLE_ERR: {
				evbuffer_add_reference(Buffer, Components[x].content, strlen(Components[x].content), NULL, NULL);
				break;
			}
		}
	}
}