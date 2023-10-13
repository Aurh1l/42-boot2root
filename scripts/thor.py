import re
from turtle import *

turtle_path = "./turtle"


def draw_turtle(instruction):
    if re.search("droite", instruction) is not None:
        droite = re.search("droite de ([0-9]*)", instruction).group(1)
        right(int(droite))
    elif re.search("gauche", instruction) is not None:
        gauche = re.search("gauche de ([0-9]*)", instruction).group(1)
        left(int(gauche))
    elif re.search("Avance", instruction) is not None:
        avance = re.search("Avance ([0-9]*)", instruction).group(1)
        forward(int(avance))
    elif re.search("Recule", instruction) is not None:
        recule = re.search("Recule ([0-9]*)", instruction).group(1)
        backward(int(recule))
    else:
        reset()
        left(90)



if __name__ == '__main__':
    with open(turtle_path, 'r') as f:
        left(90)
        for instruction in f:
            draw_turtle(instruction)