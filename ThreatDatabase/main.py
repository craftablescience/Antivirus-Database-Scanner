import requests
import xmltodict as xtd
from bs4 import BeautifulSoup as bsp
import csv
import time
import sys
import pickle as pk

dataSym = open("compilation_sym.csv", "a+", newline='')
dataSymWriter = csv.writer(dataSym)
symantecUnPickle = pk.Unpickler(open("compilation_sym_names.pkl", "rb"))
try:
    symantecExistingNames = symantecUnPickle.load()
except EOFError:
    symantecExistingNames = list()

dataKas = open("compilation_kas.csv", "a+", newline='')
dataKasWriter = csv.writer(dataKas)
kasperskyUnPickle = pk.Unpickler(open("compilation_kas_names.pkl", "rb"))
try:
    kasperskyExistingNames = kasperskyUnPickle.load()
except EOFError:
    kasperskyExistingNames = list()

dataTm = open("compilation_tm.csv", "a+", newline='')
dataTmWriter = csv.writer(dataTm)
tmUnPickle = pk.Unpickler(open("compilation_tm_names.pkl", "rb"))
try:
    tmExistingNames = kasperskyUnPickle.load()
except EOFError:
    tmExistingNames = list()

def scanCurrent():
    dataSym.seek(0, 0)
    for i, line in enumerate(dataSym.readlines()):
        if i == 0: continue
        line = line.replace('\n', '').split(',')[1]
        if line not in symantecExistingNames:
            symantecExistingNames.append(str(line))

    dataKas.seek(0, 0)
    for i, line in enumerate(dataKas.readlines()):
        if i == 0: continue
        line = line.replace('\n', '').split(',')[1]
        if line not in kasperskyExistingNames:
            kasperskyExistingNames.append(str(line))

    dataTm.seek(0, 0)
    for i, line in enumerate(dataTm.readlines()):
        if i == 0: continue
        line = line.replace('\n', '').split(',')[1]
        if line not in tmExistingNames:
            tmExistingNames.append(str(line))

    return len(symantecExistingNames) + len(kasperskyExistingNames) + len(tmExistingNames)

def crawl(csvfile, src):
    counter = 0
    new = 0
    if src == "Symantec":
        symantecFeedThreats = xtd.parse(requests.get("https://www.symantec.com/content/symantec/english/en/security-center/srlistingRssFeedXml/threats.rss.feed").content)
        symantecFeedRisks   = xtd.parse(requests.get("https://www.symantec.com/content/symantec/english/en/security-center/srlistingRssFeedXml/risks.rss.feed").content)
        symantecFeedVulns   = xtd.parse(requests.get("https://www.symantec.com/content/symantec/english/en/security-center/srlistingRssFeedXml/vulnarabilities.rss.feed").content)

        for item in symantecFeedThreats["rss"]["channel"]["item"]:
            item["title"] = item["title"].replace(",", "").replace("\"", "")
            counter += 1
            if item["title"] not in symantecExistingNames:
                new += 1
                csvfile.writerow([src, item["title"], "Threat", str(item["pubDate"]).strip(' ').replace('\n', '').replace('\"', ''), item["link"]])
                symantecExistingNames.append(item["title"])
        for item in symantecFeedRisks["rss"]["channel"]["item"]:
            item["title"] = item["title"].replace(",", "").replace("\"", "")
            counter += 1
            if item["title"] not in symantecExistingNames:
                new += 1
                csvfile.writerow([src, item["title"], "Risk", str(item["pubDate"]).strip(' ').replace('\n', '').replace('\"', ''), item["link"]])
                symantecExistingNames.append(item["title"])
        for item in symantecFeedVulns["rss"]["channel"]["item"]:
            item["title"] = item["title"].replace(",", "").replace("\"", "")
            counter += 1
            if item["title"] not in symantecExistingNames:
                new += 1
                csvfile.writerow([src, item["title"], "Vulnerability", str(item["pubDate"]).strip(' ').replace('\n', '').replace('\"', ''), item["link"]])
                symantecExistingNames.append(item["title"])

    elif src == "Kaspersky":
        kasperskyFeedThreats = list(bsp(requests.get("https://threats.kaspersky.com/en/threat/?s_post_type=threat&orderby=detect_date&meta_key=true&order=DESC").content, "lxml").find_all("td")[2:])
        kasperskyFeedVulns   = list(bsp(requests.get("https://threats.kaspersky.com/en/vulnerability/?s_post_type=vulnerability&orderby=detect_date&meta_key=true&order=DESC").content, "lxml").find_all("td")[5:])

        for i in range(0, len(kasperskyFeedThreats), 2):
            name = str(kasperskyFeedThreats[i])[126:-20].split("\n")[1].strip(" ").replace(",", "")
            counter += 1
            if name not in kasperskyExistingNames:
                new += 1
                csvfile.writerow([src, name, "Threat", str(kasperskyFeedThreats[i+1])[32:-5].strip(" "), "NA"])
                kasperskyExistingNames.append(name)
        for i in range(5, len(kasperskyFeedVulns), 6):
            name = str(kasperskyFeedVulns[i])[126:-20].strip(" ").replace(",", "")
            #print(name)
            counter += 1
            if name not in kasperskyExistingNames:
                new += 1
                #date = str(kasperskyFeedVulns[i+3])[4:-5].strip(" ")
                date = str(kasperskyFeedVulns[i+4]).strip(" ").split('\n')[20][6:-7]
                csvfile.writerow([src, name, "Vulnerability", date, name])
                kasperskyExistingNames.append(name)

    elif src == "TrendMicro":
        progress = 0
        for i in range(50):
            if i%2 == 0: progress += 1
            print("\r    [" + str(progress * "█") + str((50-progress) * '-') + "]", end='')
            for item in list(bsp(requests.get("https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/page/" + str(i+1)).content, "lxml").find_all("li", {"class": "archieveLib"})):
                name = str(item.div.div.a.string).replace('\"', '').strip(' ').replace('\n', '')
                counter += 1
                if name not in tmExistingNames:
                    new += 1
                    csvfile.writerow([src, name, "Threat", str(bsp(requests.get("https://www.trendmicro.com" + str(item.div.div.a.get("href"))).content, "lxml").find("div", {"id": "datePub"}).prettify().split('\n')[1].strip(' ').replace('\"', '')).replace('\n', ''), str(item.div.p.prettify().split('\n')[1].strip(' ').replace(',', '').replace('\"', '')).replace('\n', '')])
                    tmExistingNames.append(name)
        progress = 25
        for i in range(50):
            if i%2 == 0: progress += 1
            print("\r    [" + str(progress * "█") + str((50-progress) * '-') + "]", end='')
            for item in list(bsp(requests.get("https://www.trendmicro.com/vinfo/us/threat-encyclopedia/vulnerability/all-vulnerabilities/page/" + str(i+1)).content, "lxml").find_all("div", {"class": "sectionRow"})):
                name = item.find("div", {"class": "descTitle"}).prettify().split('\n')[2].strip('\"').strip(' ').replace('\n', '')
                date = item.find("i",   {"class": "fa-calendar-o"}).find_parent().prettify().split('\n')[3][29:].replace('\"', '').strip(' ').replace('\n', '')
                desc = item.find("div", {"id":    "listDescVul"}).prettify().split('\n')[3].replace('\"', '').strip(' ').replace('\n"', '').replace("\r", "")

                if '\n' in desc:
                    raise
                if desc[0] == '*': continue
                else: counter += 1
                if name not in tmExistingNames:
                    new += 1
                    csvfile.writerow([src, name, "Vulnerability", date, desc.replace('\n','')])
                    tmExistingNames.append(name)
        print("\r")
    return (counter, new)

def merge():
    symfile = open("compilation_sym.csv", "r")
    kasfile = open("compilation_kas.csv", "r")
    tmfile  = open("compilation_tm.csv",  "r")
    cgmfile = open("compilation.csv",     "w")

    cgmfile.write("Src,Name,Type,Date,Desc\n")
    cgmfile.writelines(symfile.readlines()[1:])
    cgmfile.writelines(kasfile.readlines()[1:])
    cgmfile.writelines(tmfile.readlines()[1:])

    symfile.close()
    kasfile.close()
    tmfile.close()
    cgmfile.close()

def end(code=0):
    dataSym.close()
    dataKas.close()
    symantecPickle = pk.Pickler(open("compilation_sym_names.pkl", "wb"))
    symantecPickle.dump(symantecExistingNames)
    kasperskyPickle = pk.Pickler(open("compilation_kas_names.pkl", "wb"))
    kasperskyPickle.dump(kasperskyExistingNames)
    tmPickle = pk.Pickler(open("compilation_tm_names.pkl", "wb"))
    tmPickle.dump(tmExistingNames)
    print("[!] Merging...")
    merge()
    print("[*] Exiting with code " + str(code) + ".")
    quit(code)

def main():
    print("[!] Scanning current database...")
    print("[*] " + str(scanCurrent()) + " malware found in database.")

    print("[!] Scanning Symantec for changes...")
    sym = crawl(dataSymWriter, "Symantec")
    print("[*] " + str(sym[0]) + " malware found, " + str(sym[1]) + " new.")

    print("[!] Scanning Kaspersky for changes...")
    kas = crawl(dataKasWriter, "Kaspersky")
    print("[*] " + str(kas[0]) + " malware found, " + str(kas[1]) + " new.")

    print("[!] Scanning TrendMicro for changes...")
    tm = crawl(dataTmWriter, "TrendMicro")
    print("[*] " + str(tm[0]) + " malware found, " + str(tm[1]) + " new.")

    timer = 86400
    while timer != 0:
        print("\r[@] " + str(int(timer/3600)) + ":" + str(int(timer/60)%60) + ":" + str(timer%60) + " remaining until next scan.", end='')
        timer -= 1
        time.sleep(1)
    print("\r[@] 0 minutes 0 seconds remaining until next scan.")

if __name__ == "__main__":
    print("[*] MALWARE DATABASE COMPILER")

    try:
        while True:
            main()
    except KeyboardInterrupt:
        print("\n[*] User-requested shutdown initiated.")
        end()