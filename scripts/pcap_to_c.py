import os
import re

ft_fun_path = "./ft_fun"
tab = {}

if __name__ == '__main__':
    for filename in os.listdir(ft_fun_path):
        with open(os.path.join(ft_fun_path, filename), 'r') as f:
            print(f"Reading {filename}")
            content = f.read()
            file_number = int(re.search(r'//file([0-9]*)', content).group(1))
            tab[file_number] = re.sub("//file[0-9]*", "", content)

    with(open("challenge.c", "w+")) as challenge:
        for _, value in sorted(tab.items()):
            challenge.write(value)
        challenge.close()

