import os


def read_log():
    my_checks_db = dict()
    for j in range(1, 8):
        file = "/tmp/log{checkNum}".format(checkNum=j)
        List = []
        if os.path.exists(file):
            with open(file, 'r') as file:
                data = file.read().split("*******", 20)
                i = 1
                while i < len(data):
                    List.append(data[i])
                    i += 1
            my_checks_db[j] = {}
            for line in range(0, len(List)-1, 2):
                my_checks_db[j][List[line]] = List[line+1]
    return my_checks_db
