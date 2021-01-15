import json
import requests
import os
import sys
import time
import datetime
from threading import Thread

res = [0]*100000
count = 0
directory = os.path.abspath(__file__)[:os.path.abspath(__file__).rfind('\\')]
api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
file_extensions = ['.exe', '.dll']
params = dict(apikey='')
i = 0
def ScanFile(f, i1):
    global count
    with open(f, 'rb') as file:
          files = dict(file=(f[f.rfind("\\") + 1:], file))
          response = requests.post(api_url, files=files, params=params)
          if response.status_code == 200:
              result=response.json()["permalink"]
              result=result[:result.rfind('/')]
              res[i1] = f[f.rfind("\\") + 1:] + ": " + result + "\n"
              with open('results.txt', 'a') as ff:
                  ff.write(f[f.rfind("\\") + 1:] + ": " + result + "\n")
          else:
              print("Во время отправки " + f + " возникла ошибка: " + str(response))
          count += 1
def main():
    global i
    print("Сканирование начато")
    d = datetime.datetime.now().strftime("%d-%m-%Y %H:%M")
    with open(directory + '\\results.txt', 'w') as f1:
        f1.write(d + "\n")
    for root, dirs, files in os.walk(directory):
        for f in files:
            if directory + '\\' + f != os.path.abspath(__file__) and f != "results.txt":
                path = os.path.join(root, f)
                filename = path[path.rfind('\\') + 1:]
                if filename[filename.rfind('.'):] not in file_extensions:
                    continue
                print("Загружается файл " + filename)
                thread = Thread(target=ScanFile, args=(path, i))
                thread.start()
                time.sleep(0.5)
                i += 1
    return d
time = main()
while count < i: continue
with open(directory + '\\results.txt', 'w') as f1:
        f1.write(time + "\n")
for s in range(0, i):
    with open('results.txt', 'a') as ff:
        ff.write(res[s])
print("\nЗавершена проверка " + str(i) + " файлов")
