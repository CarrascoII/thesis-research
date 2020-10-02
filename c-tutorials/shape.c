#include <stdio.h>
#include <stdlib.h>
#include <math.h>

typedef struct _shape shape;

typedef void* (*create_func)(double);
typedef void (*print_func)(void*);
typedef double (*perimeter_func)(void*);
typedef double (*area_func)(void*);

typedef struct _shape {
    void *instance;

    // Vtable
    create_func init_shape;
    print_func print;
    perimeter_func calc_perimeter;
    area_func calc_area;
} shape;

shape *create_shape(void *create, void *print, void *perimeter, void *area) {
    shape *shape = (struct _shape*) malloc(sizeof(struct _shape));

    shape->init_shape = ((create_func) create);
    shape->print = (print_func) print;
    shape->calc_perimeter = (perimeter_func) perimeter;
    shape->calc_area = (area_func) area;

    return shape;
}

void print_shape(shape *shape) {
    (shape->print)(shape->instance);
}

double calc_shape_perimeter(shape *shape) {
    return (shape->calc_perimeter)(shape->instance);
}

double calc_shape_area(shape *shape) {
    return (shape->calc_area)(shape->instance);
}

// Square implementation
typedef struct _square {
    double x;
} square;

void* create_square(double sideLength) {
    square *square = (struct _square*) malloc(sizeof(struct _square));
    square->x = sideLength;
    
    return (void*) square;
}

void print_square(square *square) {
    printf("This shape is a square with x=%f\n", square->x);
}

double calc_square_perimeter(square *square) {
    return 4 * square->x;
}

double calc_square_area(square *square) {
    return square->x * square->x;
}

// Circle implementation
typedef struct _circle {
    double radius;
} circle;

void* create_circle(double radius) {
    circle *circle = (struct _circle *) malloc(sizeof(struct _circle));
    circle->radius = radius;
    
    return (void*) circle;
}

void print_circle(circle *circle) {
    printf("This shape is a circle with r=%f\n", circle->radius);
}

double calc_circle_perimeter(circle *circle) {
    return 2 * M_PI * circle->radius;
}

double calc_circle_area(circle *circle){
    return M_PI * (circle->radius * circle->radius);
}

// Test
int main() {
    shape *square = create_shape(&create_square, &print_square, &calc_square_perimeter, &calc_square_area);
    shape *circle = create_shape(&create_circle, &print_circle, &calc_circle_perimeter, &calc_circle_area);

    square->instance = square->init_shape(5.0);
    circle->instance = square->init_shape(5.0);

    // Sanity check.
    print_shape(square);
    printf("Perimeter: %f | Area: %f\n", calc_shape_perimeter(square), calc_shape_area(square));

    print_shape(circle);
    printf("Perimeter: %f | Area: %f\n", calc_shape_perimeter(circle), calc_shape_area(circle));

    // Free up memory
    free(circle);
    free(square);
//    free(circle);
//    free(square);

    return 0;
}