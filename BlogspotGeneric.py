import sys
import requests
import bs4

def run():
	main = requests.get("http://???.blogspot.com/").text
	soup = bs4.BeautifulSoup(main)
	articlesSoup = soup.find_all("h3", {"class": "post-title entry-title"})
	articles = []

	for x in articlesSoup:
		articles.append(x.find("a").attrs["href"])

	ret = "setType1\n"

	for x in articles:
		article = requests.get(x).text
		soup = bs4.BeautifulSoup(article)
		pres = soup.find("pre", {"class": "alt2"}).findAll("span", {"style": "font-weight: bold;"});
		for i in pres:
			ret += i.text;
	return ret

print run()
