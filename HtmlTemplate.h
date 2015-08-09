#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "Interface.h"

bool HtmlTemplateUseStock;

typedef struct _HTML_TEMPLATE_MIME_TYPE {
	char *extension;
	char *type;
} HTML_TEMPLATE_MIME_TYPE;

HTML_TEMPLATE_MIME_TYPE *HtmlTemplateMimeTypes;
size_t HtmlTemplateMimeTypesSize;

typedef enum _HTML_TEMPLATE_COMPONENT_TYPE {
	STATIC,
	FROM_CFG,
	DYNAMIC,
	TABLE
} HTML_TEMPLATE_COMPONENT_TYPE;

typedef struct _HTML_TEMPLATE_COMPONENT {
	HTML_TEMPLATE_COMPONENT_TYPE type;
	char *name;
	void *content;
} HTML_TEMPLATE_COMPONENT;

typedef enum _HTML_TEMPLATE_TABLE {
	HTML_TEMPLATE_TABLE_UPROXIES,
	HTML_TEMPLATE_TABLE_PROXIES,
	HTML_TEMPLATE_TABLE_PRXSRC
} HTML_TEMPLATE_TABLE;

typedef struct _HTML_TEMPALTE_TABLE_INFO {
	bool inTable;
	size_t x;
	size_t iteration;
	void *tableObject;
	HTML_TEMPLATE_TABLE table;
} HTML_TEMPALTE_TABLE_INFO;

HTML_TEMPLATE_COMPONENT *HtmlTemplateDynamic;
size_t HtmlTemplateDynamicSize;

// T_VERSION, T_CURRENT_PAGE, T_CFG_HOME_ACTIVE, T_CFG_UPROXIES_ACTIVE, T_CFG_PROXIES_ACTIVE, T_CFG_SOURCES_ACTIVE, T_CFG_STATS_ACTIVE
HTML_TEMPLATE_COMPONENT **HtmlTemplateHead;
size_t HtmlTemplateHeadSize;
// [none]
HTML_TEMPLATE_COMPONENT **HtmlTemplateFoot;
size_t HtmlTemplateFootSize;

// T_USER, T_COUNT_UPROXIES, T_COUNT_PROXIES
HTML_TEMPLATE_COMPONENT **HtmlTemplateHome;
size_t HtmlTemplateHomeSize;
// T_UPROXIES_HEAD_[1-5], T_UPROXIES_TABLE_ITEMS_[START/END], T_CFG_TABLE_ODD, T_CFG_TABLE_EVEN, T_CFG_TABLE_OK, T_CFG_TABLE_WARN, T_CFG_TABLE_ERR, T_UPROXIES_ITEM_[1-5]
HTML_TEMPLATE_COMPONENT **HtmlTemplateUProxies;
size_t HtmlTemplateUProxiesSize;
// T_PROXIES_HEAD_[1-12], T_PROXIES_TABLE_ITEMS_[START/END], T_CFG_TABLE_ODD, T_CFG_TABLE_EVEN, T_CFG_TABLE_OK, T_CFG_TABLE_WARN, T_CFG_TABLE_ERR, T_PROXIES_ITEM_[1-12]
HTML_TEMPLATE_COMPONENT **HtmlTemplateProxies;
size_t HtmlTemplateProxiesSize;
// T_PRXSRC_HEAD_[1-3], T_PRXSRC_TABLE_ITEMS_[START/END], T_CFG_TABLE_ODD, T_CFG_TABLE_EVEN, T_CFG_TABLE_OK, T_CFG_TABLE_WARN, T_CFG_TABLE_ERR, T_PRXSRC_ITEM_[1-3]
HTML_TEMPLATE_COMPONENT **HtmlTemplateProxySources;
size_t HtmlTemplateProxySourcesSize;

void HtmlTemplateParse(FILE *hFile, HTML_TEMPLATE_COMPONENT ***Template, size_t *SizeRef);
void HtmlTemplateLoadAll();
void HtmlTemplateBufferInsert(struct evbuffer *Buffer, HTML_TEMPLATE_COMPONENT **Components, size_t Size, INTERFACE_INFO Info, HTML_TEMPALTE_TABLE_INFO TableInfo);
void HtmlTemplateMimeTypesInit();