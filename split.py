

List = []
with open('/tmp/log1', 'r') as file:
    data = file.read().split("*******",20)
    i = 1
    while i < 8 :
        List.append(data[i])
        print(List[i-1])
        i +=1