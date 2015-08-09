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

	/* Fill up dynamic components */ {
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

#define CONFIG_STRING(cfg, svar, var) const char *val; if (config_setting_lookup_string(cfg, svar, &val) == CONFIG_FALSE) { Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %s...", svar); HtmlTemplateUseStock = true; return; } else { var = malloc((strlen(val) * sizeof(char)) + 1); strcpy(var, val); }

		HtmlTemplateDynamicSize = 60;

		HtmlTemplateDynamic = malloc(HtmlTemplateDynamicSize * sizeof(HTML_TEMPLATE_COMPONENT));
		for (size_t x = 0;x < HtmlTemplateDynamicSize;x++) {
			HTML_TEMPLATE_COMPONENT *comp = &(HtmlTemplateDynamic[x]);
			comp->type = DYNAMIC;
			switch (x) {
				case 0: {
					comp->name = "{T_VERSION}";
					comp->content = VERSION;
					break;
				}
				case 1: {
					comp->name = "{T_CURRENT_PAGE}";
					comp->content = NULL;
					break;
				}
				case 2: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_HOME_ACTIVE}";
					CONFIG_STRING(cfgRoot, "HomeActive", comp->content)
						break;
				}
				case 3: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_UPROXIES_ACTIVE}";
					CONFIG_STRING(cfgRoot, "UProxiesActive", comp->content)
						break;
				}
				case 4: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_PROXIES_ACTIVE}";
					CONFIG_STRING(cfgRoot, "ProxiesActive", comp->content)
						break;
				}
				case 5: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_SOURCES_ACTIVE}";
					CONFIG_STRING(cfgRoot, "SourcesActive", comp->content)
						break;
				}
				case 6: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_STATS_ACTIVE}";
					CONFIG_STRING(cfgRoot, "StatsActive", comp->content)
						break;
				}
				case 7: {
					comp->name = "{T_USER}";
					comp->content = NULL;
					break;
				}
				case 8: {
					comp->name = "{T_COUNT_UPROXIES}";
					comp->content = &sizeUncheckedProxies;
					break;
				}
				case 9: {
					comp->name = "{T_COUNT_PROXIES}";
					comp->content = &sizeCheckedProxies;
					break;
				}
				case 10:
				case 11:
				case 12:
				case 13:
				case 14: {
					comp->name = malloc((20 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_UPROXIES_HEAD_%d}", x - 9);
					comp->content = NULL;
					break;
				}
				case 15: {
					comp->type = TABLE;
					comp->name = "{T_UPROXIES_TABLE_ITEMS_START}";
					comp->content = NULL;
					break;
				}
				case 16: {
					comp->type = TABLE;
					comp->name = "{T_UPROXIES_TABLE_ITEMS_END}";
					comp->content = NULL;
					break;
				}
				case 17: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_TABLE_ODD}";
					CONFIG_STRING(cfgRoot, "TableOdd", comp->content)
						break;
				}
				case 18: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_TABLE_EVEN}";
					CONFIG_STRING(cfgRoot, "TableOdd", comp->content)
						break;
				}
				case 19: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_TABLE_OK}";
					CONFIG_STRING(cfgRoot, "TableOk", comp->content)
						break;
				}
				case 20: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_TABLE_WARN}";
					CONFIG_STRING(cfgRoot, "TableWarn", comp->content)
						break;
				}
				case 21: {
					comp->type = FROM_CFG;
					comp->name = "{T_CFG_TABLE_ERR}";
					CONFIG_STRING(cfgRoot, "TableError", comp->content)
						break;
				}
				case 22:
				case 23:
				case 24:
				case 25:
				case 26: {
					comp->name = malloc((20 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_UPROXIES_ITEM_%d}", x - 21);
					comp->content = NULL;
					break;
				}
				case 27: case 28: case 29:
				case 30: case 31: case 32:
				case 33: case 34: case 35:
				case 36: case 37: case 38: {
					comp->name = malloc((19 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_PROXIES_HEAD_%d}", x - 26);
					comp->content = NULL;
					break;
				}
				case 39: {
					comp->type = TABLE;
					comp->name = "{T_PROXIES_TABLE_ITEMS_START}";
					comp->content = NULL;
					break;
				}
				case 40: {
					comp->type = TABLE;
					comp->name = "{T_PROXIES_TABLE_ITEMS_END}";
					comp->content = NULL;
					break;
				}
				case 41: case 42: case 43:
				case 44: case 45: case 46:
				case 47: case 48: case 49:
				case 50: case 51: case 52: {
					comp->name = malloc((19 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_PROXIES_ITEM_%d}", x - 40);
					comp->content = NULL;
					break;
				}
				case 53:
				case 54:
				case 55: {
					comp->name = malloc((19 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_PRXSRC_HEAD_%d}", x - 52);
					comp->content = NULL;
					break;
				}
				case 56: {
					comp->type = TABLE;
					comp->name = "{T_PRXSRC_TABLE_ITEMS_START}";
					comp->content = NULL;
					break;
				}
				case 57: {
					comp->type = TABLE;
					comp->name = "{T_PRXSRC_TABLE_ITEMS_END}";
					comp->content = NULL;
					break;
				}
				case 58:
				case 59:
				case 60: {
					comp->name = malloc((19 * sizeof(char)) + 1);
					sprintf(comp->name, "{T_PRXSRC_ITEM_%d}", x - 57);
					comp->content = NULL;
					break;
				}
			}
		}
		config_destroy(&cfg);
#undef CONFIG_STRING
	} /* End fill up dynamic components */

	DIR *d;
	struct dirent *dir;
	uint8_t itemsFound = 0;
	bool fullPath = false;

	d = opendir("./html");
	if (!d) {
		d = opendir("/etc/liveproxies/html");
		fullPath = true;
	}

	char *files[] = { "head.tmpl", "foot.tmpl", "home.tmpl", "iface.tmpl", "ifaceu.tmpl", "prxsrc.tmpl" };

	if (d) {
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
							HtmlTemplateParse(hFile, &HtmlTemplateHead, &HtmlTemplateHeadSize);
						if (strcmp(dir->d_name, "foot.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateFoot, &HtmlTemplateFootSize);
						if (strcmp(dir->d_name, "home.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateHome, &HtmlTemplateHomeSize);
						if (strcmp(dir->d_name, "iface.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateProxies, &HtmlTemplateProxiesSize);
						if (strcmp(dir->d_name, "ifaceu.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateUProxies, &HtmlTemplateUProxiesSize);
						if (strcmp(dir->d_name, "prxsrc.tmpl") == 0)
							HtmlTemplateParse(hFile, &HtmlTemplateProxySources, &HtmlTemplateProxySourcesSize);

						itemsFound++;
					}
				}
			}
		}

		if (itemsFound != 6) {
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

static void HtmlTemplateFindFirst(char *Contents, OUT HTML_TEMPLATE_COMPONENT **Component, OUT char **Offset)
{
	*Offset = SIZE_MAX;
	*Component = NULL;

	for (size_t x = 0;x < HtmlTemplateDynamicSize;x++) {
		char *cur = strstr(Contents, HtmlTemplateDynamic[x].name);
		if (cur != NULL && cur < *Offset) {
			*Offset = cur;
			*Component = &(HtmlTemplateDynamic[x]);
		}
	}
	if (*Component != NULL)
		Log(LOG_LEVEL_DEBUG, "HtmlTemplateFindFirst: %s", (*Component)->name);
	else
		Log(LOG_LEVEL_DEBUG, "HtmlTemplateFindFirst: NULL");
}

static void HtmlTemplateComponentPush(HTML_TEMPLATE_COMPONENT ***Components, size_t *CurrentSize, HTML_TEMPLATE_COMPONENT *Component)
{
	(*CurrentSize)++;

	*Components = *CurrentSize == 1 ? malloc(*CurrentSize * sizeof(*Components)) : realloc(*Components, *CurrentSize * sizeof(*Components));
	(*Components)[*CurrentSize - 1] = Component;
}

void HtmlTemplateParse(FILE *hFile, HTML_TEMPLATE_COMPONENT ***Template, size_t *SizeRef)
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

	HTML_TEMPLATE_COMPONENT *comp;
	char *offset;
	/*HtmlTemplateFindFirst(string, &comp, &offset);

	if (comp == NULL) {
		// No dynamic components
		comp = malloc(sizeof(HTML_TEMPLATE_COMPONENT));
		comp->type = STATIC;
		comp->name = NULL;
		comp->content = malloc((strlen(string) * sizeof(char)) + 1);
		strcpy(comp->content, string);
		HtmlTemplateComponentPush(HtmlTemplateHead, &componentsSize, comp);
		return;
	} else {
		// Copy static start
		comp = malloc(sizeof(HTML_TEMPLATE_COMPONENT));
		comp->type = STATIC;
		comp->name = NULL;
		comp->content = malloc(offset - string + 1);
		strncpy(comp->content, string, offset - string);
		HtmlTemplateComponentPush(HtmlTemplateHead, &componentsSize, comp);
		curEnd = offset;
	}*/

	while (1) {
		Log(LOG_LEVEL_DEBUG, "Finding first...");
		HtmlTemplateFindFirst(curEnd, &comp, &offset);

		if (comp == NULL) {
			Log(LOG_LEVEL_DEBUG, "No more components");
			// No more components
			comp = malloc(sizeof(HTML_TEMPLATE_COMPONENT));
			comp->type = STATIC;
			comp->name = NULL;
			comp->content = malloc((strlen(curEnd) * sizeof(char)) + 1);
			strcpy(comp->content, curEnd);
			HtmlTemplateComponentPush(Template, SizeRef, comp);
			break;
		} else {
			if (offset != curEnd) {
				Log(LOG_LEVEL_DEBUG, "Pushing static content...");
				// Push static content in front of component
				HTML_TEMPLATE_COMPONENT *compStatic = malloc(sizeof(HTML_TEMPLATE_COMPONENT));
				compStatic->type = STATIC;
				compStatic->name = NULL;
				compStatic->content = malloc(offset - curEnd + 1);
				strncpy(compStatic->content, curEnd, offset - curEnd);
				((char*)(compStatic->content))[offset - curEnd] = 0x00;

				Log(LOG_LEVEL_DEBUG, "Static content: %s", compStatic->content);

				HtmlTemplateComponentPush(Template, SizeRef, compStatic);
				curEnd = offset;
			}
			if (offset == curEnd) {
				Log(LOG_LEVEL_DEBUG, "Pushing dynamic content...");
				// Push dynamic content
				HtmlTemplateComponentPush(Template, SizeRef, comp);
				curEnd = offset + strlen(comp->name);
			}
		}
		Log(LOG_LEVEL_DEBUG, "Size: %d", *SizeRef);
	}
}

void HtmlTemplateBufferInsert(struct evbuffer *Buffer, HTML_TEMPLATE_COMPONENT **Components, size_t Size, INTERFACE_INFO Info, HTML_TEMPALTE_TABLE_INFO TableInfo)
{
	uint8_t rowStatus = 0;

	switch (TableInfo.table) {
		case HTML_TEMPLATE_TABLE_UPROXIES: {
			// No color
			rowStatus = 0;
			break;
		}
		case HTML_TEMPLATE_TABLE_PROXIES: {
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


	Log(LOG_LEVEL_DEBUG, "TableInfo:");
	Log(LOG_LEVEL_DEBUG, ".x: %d", TableInfo.x);
	Log(LOG_LEVEL_DEBUG, ".inTable: %s", TableInfo.inTable ? "true" : "false");
	Log(LOG_LEVEL_DEBUG, ".iteration: %d", TableInfo.iteration);
	Log(LOG_LEVEL_DEBUG, ".table: %d", TableInfo.table);
	Log(LOG_LEVEL_DEBUG, ".tableObject: %p", TableInfo.tableObject);

	Log(LOG_LEVEL_DEBUG, "Size: %d", Size);

	for (size_t x = TableInfo.x;x < Size;x++) {
		Log(LOG_LEVEL_DEBUG, "Component (%d): ", x);
		Log(LOG_LEVEL_DEBUG, "->name: %s", Components[x]->name);
		Log(LOG_LEVEL_DEBUG, "->content: %s", Components[x]->content);
		Log(LOG_LEVEL_DEBUG, "->type: %d", Components[x]->type);

		switch (Components[x]->type) {
			case STATIC:
			case FROM_CFG: {
				if (Components[x]->name != NULL) {
					if (strcmp(Components[x]->name, "{T_CFG_HOME_ACTIVE}") == 0 && Info.currentPage->page != INTERFACE_PAGE_HOME)
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_UPROXIES_ACTIVE}") == 0 && Info.currentPage->page != INTERFACE_PAGE_UPROXIES)
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_PROXIES_ACTIVE}") == 0 && Info.currentPage->page != INTERFACE_PAGE_PROXIES)
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_SOURCES_ACTIVE}") == 0 && Info.currentPage->page != INTERFACE_PAGE_PRXSRC)
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_STATS_ACTIVE}") == 0 && Info.currentPage->page != INTERFACE_PAGE_STATS)
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_TABLE_ODD}") == 0 && (!TableInfo.inTable || TableInfo.iteration % 2 == 0))
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_TABLE_EVEN}") == 0 && (!TableInfo.inTable || TableInfo.iteration % 2 != 0))
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_TABLE_OK}") == 0 && (!TableInfo.inTable || rowStatus != 1))
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_TABLE_WARN}") == 0 && (!TableInfo.inTable || rowStatus != 2))
						continue;
					else if (strcmp(Components[x]->name, "{T_CFG_TABLE_ERR}") == 0 && (!TableInfo.inTable || rowStatus != 3))
						continue;
				}
				evbuffer_add_reference(Buffer, Components[x]->content, strlen(Components[x]->content), NULL, NULL);
				break;
			}
			case DYNAMIC: {
				if (strcmp(Components[x]->name, "{T_VERSION}") == 0)
					evbuffer_add_reference(Buffer, Components[x]->content, strlen(Components[x]->content), NULL, NULL);
				else if (strcmp(Components[x]->name, "{T_CURRENT_PAGE}") == 0)
					evbuffer_add_reference(Buffer, Info.currentPage->name, strlen(Info.currentPage->name), NULL, NULL);
				else if (strcmp(Components[x]->name, "{T_USER}") == 0)
					evbuffer_add_reference(Buffer, Info.user, strlen(Info.user), NULL, NULL);
				else if (strcmp(Components[x]->name, "{T_COUNT_UPROXIES}") == 0 || strcmp(Components[x]->name, "{T_COUNT_PROXIES}") == 0)
					evbuffer_add_printf(Buffer, "%d", *((size_t*)(Components[x]->content)));
				if (!TableInfo.inTable) {
					if (Info.currentPage->page == INTERFACE_PAGE_UPROXIES) {
						if (strcmp(Components[x]->name, "{T_UPROXIES_HEAD_1}") == 0)
							evbuffer_add_reference(Buffer, "IP:Port", 7, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_UPROXIES_HEAD_2}") == 0)
							evbuffer_add_reference(Buffer, "Type", 4, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_UPROXIES_HEAD_3}") == 0)
							evbuffer_add_reference(Buffer, "Currently checking", 18, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_UPROXIES_HEAD_4}") == 0)
							evbuffer_add_reference(Buffer, "Retries", 7, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_UPROXIES_HEAD_5}") == 0)
							evbuffer_add_reference(Buffer, "Rechecking", 10, NULL, NULL);
					} else if (Info.currentPage->page == INTERFACE_PAGE_PROXIES) {
						if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_1}") == 0)
							evbuffer_add_reference(Buffer, "IP:Port", 7, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_2}") == 0)
							evbuffer_add_reference(Buffer, "Type", 4, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_3}") == 0)
							evbuffer_add_reference(Buffer, "Country", 7, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_4}") == 0)
							evbuffer_add_reference(Buffer, "Anonymity", 9, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_5}") == 0)
							evbuffer_add_reference(Buffer, "Connection latency (ms)", 23, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_6}") == 0)
							evbuffer_add_reference(Buffer, "HTTP/S latency (ms)", 19, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_7}") == 0)
							evbuffer_add_reference(Buffer, "Live since", 10, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_8}") == 0)
							evbuffer_add_reference(Buffer, "Last checked", 12, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_9}") == 0)
							evbuffer_add_reference(Buffer, "Retries", 7, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_10}") == 0)
							evbuffer_add_reference(Buffer, "Successful checks", 17, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_11}") == 0)
							evbuffer_add_reference(Buffer, "Failed checks", 13, NULL, NULL);
						else if (strcmp(Components[x]->name, "{T_PROXIES_HEAD_12}") == 0)
							evbuffer_add_reference(Buffer, "Full check", 10, NULL, NULL);
					}
				} else {
					switch (TableInfo.table) {
						case HTML_TEMPLATE_TABLE_UPROXIES: {
							UNCHECKED_PROXY *uproxy = (UNCHECKED_PROXY*)TableInfo.tableObject;
							if (strcmp(Components[x]->name, "{T_UPROXIES_ITEM_1}") == 0) {
								char *ip = IPv6MapToString2(uproxy->ip); {
									evbuffer_add_printf(Buffer, "%s:%d", ip, uproxy->port);
								} free(ip);
							}
							if (strcmp(Components[x]->name, "{T_UPROXIES_ITEM_2}") == 0)
								evbuffer_add_printf(Buffer, "%s", ProxyGetTypeString(uproxy->type));
							if (strcmp(Components[x]->name, "{T_UPROXIES_ITEM_3}") == 0)
								evbuffer_add_reference(Buffer, uproxy->checking ? "check" : "x", uproxy->checking ? 5 : 1, NULL, NULL);
							if (strcmp(Components[x]->name, "{T_UPROXIES_ITEM_4}") == 0)
								evbuffer_add_printf(Buffer, "%d", uproxy->retries);
							if (strcmp(Components[x]->name, "{T_UPROXIES_ITEM_5}") == 0)
								evbuffer_add_reference(Buffer, uproxy->associatedProxy != NULL ? "check" : "x", uproxy->associatedProxy != NULL ? 5 : 1, NULL, NULL);
							break;
						}
						case HTML_TEMPLATE_TABLE_PROXIES: {
							PROXY *proxy = (PROXY*)TableInfo.tableObject;
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_1}") == 0) {
								char *ip = IPv6MapToString2(proxy->ip); {
									evbuffer_add_printf(Buffer, "%s:%d", ip, proxy->port);
								} free(ip);
							}
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_2}") == 0)
								evbuffer_add_printf(Buffer, "%s", ProxyGetTypeString(proxy->type));
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_3}") == 0)
								evbuffer_add_reference(Buffer, proxy->country, 2, NULL, NULL);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_4}") == 0) {
								if (proxy->anonymity == ANONYMITY_MAX)
									evbuffer_add_reference(Buffer, "Max", 3, NULL, NULL);
								else if (proxy->anonymity == ANONYMITY_ANONYMOUS)
									evbuffer_add_reference(Buffer, "Anonymous", 9, NULL, NULL);
								else if (proxy->anonymity == ANONYMITY_TRANSPARENT)
									evbuffer_add_reference(Buffer, "Transparent", 11, NULL, NULL);
								else
									evbuffer_add_reference(Buffer, "N/A", 3, NULL, NULL);
							}
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_5}") == 0)
								evbuffer_add_printf(Buffer, "%d", proxy->timeoutMs);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_6}") == 0)
								evbuffer_add_printf(Buffer, "%d", proxy->httpTimeoutMs);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_7}") == 0) {
								char *time = FormatTime(proxy->liveSinceMs); {
									evbuffer_add_printf(Buffer, "%s", time);
								} free(time);
							}
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_8}") == 0) {
								char *time = FormatTime(proxy->lastCheckedMs); {
									evbuffer_add_printf(Buffer, "%s", time);
								} free(time);
							}
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_9}") == 0)
								evbuffer_add_printf(Buffer, "%d", proxy->retries);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_10}") == 0)
								evbuffer_add_printf(Buffer, "%d", proxy->successfulChecks);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_11}") == 0)
								evbuffer_add_printf(Buffer, "%d", proxy->failedChecks);
							if (strcmp(Components[x]->name, "{T_PROXIES_ITEM_12}") == 0) {
								uint8_t sid[IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)];
								memcpy(sid, proxy->ip->Data, IPV6_SIZE);
								*((uint16_t*)(sid + IPV6_SIZE)) = proxy->port;
								*((PROXY_TYPE*)(sid + IPV6_SIZE + sizeof(uint16_t))) = proxy->type;

								char *sidb64;
								Base64Encode(sid, IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE), &sidb64); {
									evbuffer_add_printf(Buffer, "<a href=\"/iface/check?sid=%s\">Check</a>", sidb64);
								} free(sidb64);
							}
							break;
						}
						case HTML_TEMPLATE_TABLE_PRXSRC: {
							assert(0);
							break;
						}
					}
				}
				break;
			}
			case TABLE: {
				if (strcmp((strlen(Components[x]->name) * sizeof(char)) + Components[x]->name - (4 * sizeof(char)), "END}") == 0) {
					Log(LOG_LEVEL_DEBUG, "End of table iteration");
					return;
				}
				if (strcmp(Components[x]->name, "{T_UPROXIES_TABLE_ITEMS_START}") == 0) {
					pthread_mutex_lock(&lockUncheckedProxies); {
						for (size_t i = 0;i < sizeUncheckedProxies;i++) {
							HTML_TEMPALTE_TABLE_INFO tableInfo;
							tableInfo.inTable = true;
							tableInfo.x = x + 1;
							tableInfo.iteration = i;
							tableInfo.table = HTML_TEMPLATE_TABLE_UPROXIES;
							tableInfo.tableObject = uncheckedProxies[i];
							HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
						}
					} pthread_mutex_unlock(&lockUncheckedProxies);
					while (Components[x]->name == NULL || strcmp((strlen(Components[x]->name) * sizeof(char)) + Components[x]->name - (4 * sizeof(char)), "END}") != 0 || x > Size)
						x++;
				}
				if (strcmp(Components[x]->name, "{T_PROXIES_TABLE_ITEMS_START}") == 0) {
					pthread_mutex_lock(&lockCheckedProxies); {
						for (size_t i = 0;i < sizeCheckedProxies;i++) {
							HTML_TEMPALTE_TABLE_INFO tableInfo;
							tableInfo.inTable = true;
							tableInfo.x = x + 1;
							tableInfo.iteration = i;
							tableInfo.table = HTML_TEMPLATE_TABLE_PROXIES;
							tableInfo.tableObject = checkedProxies[i];
							HtmlTemplateBufferInsert(Buffer, Components, Size, Info, tableInfo);
						}
					} pthread_mutex_unlock(&lockCheckedProxies);
					while (Components[x]->name == NULL || strcmp((strlen(Components[x]->name) * sizeof(char)) + Components[x]->name - (4 * sizeof(char)), "END}") != 0 || x > Size)
						x++;
				}
				break;
			}
		}
	}
}