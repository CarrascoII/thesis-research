#include <stdio.h>
#include <stdlib.h>

struct third {
    int att;
};

struct second {
    struct third *third;
};

struct first {
    struct second *second;
};

void pass(struct first *first, struct second *second) {
    first->second = second;
}

int main()
{
    struct first *first = (struct first *) malloc(sizeof(struct first));
    struct second second;
    struct second *nd = (struct second *) malloc(sizeof(struct second));
    struct third third, rd;
    
    third.att = 1;
    rd.att = 2;
    second.third = &third;
    nd->third = &rd;
    first->second = &second;

    printf("Got %d and %d\n", first->second->third->att, nd->third->att);
    pass(first, nd);
    printf("Got %d and %d\n", first->second->third->att, nd->third->att);

    free(nd);
    free(first);

    return 0;
}