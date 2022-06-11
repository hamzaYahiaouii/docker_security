

List = []
with open('/tmp/log1', 'r') as file:
    data = file.read().split("*******",20)
    i = 1
    while i < 8 :
        List.append(data[i].replace("\033[1;34m","").replace("\033[1;31m","").replace("\033[1;32m","").replace("\033[1;31m","").replace("\033[0m",""))
        print(List[i-1])
        i += 1

    








#.replace("\033[1;34m","").replace("\033[1;31m","").replace("\033[1;32m","").replace("\033[1;31m","").replace("\033[0m","")