#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "person.h"

person* new_person(const char* const first_name, const char* const last_name, const int age) {
    person* person_obj = NULL;
    
    //allocating memory
    person_obj = (person*) malloc(sizeof(person));
    if (person_obj == NULL) {
        return NULL;
    }
    person_obj->child_object = person_obj;

    person_obj->first_name = malloc(sizeof(char)*(strlen(first_name) + 1));
    if (person_obj->first_name == NULL) {
        return NULL;
    }
    strcpy(person_obj->first_name, first_name);

    person_obj->last_name = malloc(sizeof(char)*(strlen(last_name) + 1));
    if (person_obj->last_name == NULL) {
        return NULL;
    }
    strcpy(person_obj->last_name, last_name);

    person_obj->age = age;

    //Initializing interface for access to functions
    person_obj->display = display_person_info;
    person_obj->get_age = get_person_age;
    person_obj->write_to_file = write_person_to_file;
    person_obj->delete = delete_person;

    return person_obj;
}

void display_person_info(person* const person) {
    printf("Hello, I am %s %s!\n", person->first_name, person->last_name);
}

int get_person_age(person* const person) {
    return person->age;
}

void write_person_to_file(person* const person, const char* file_name) {
    printf("Writing %s %s to %s!\n", person->first_name, person->last_name, file_name);
}

void delete_person(person* const person) {
    printf("Destroying %s %s! (;-;)\n", person->first_name, person->last_name);
}

/*********************************************************************************************************/

person* new_employee(const char* const first_name, const char* const last_name, const int age,
                     const char* const company, const char* const department, int salary) {

    // Calling base class construtor
    employee* employee_obj;
    person* person_obj = new_person(first_name, last_name, age);
    
    //allocating memory
    employee_obj = malloc(sizeof(employee));
    if (employee_obj == NULL) {
        person_obj->delete(person_obj);
        return NULL;
    }
    person_obj->child_object = employee_obj; // pointing to child object

    //initialising derived class members
    employee_obj->company = malloc(sizeof(char)*(strlen(company)+1));
    if(employee_obj->company== NULL) {
        return NULL;
    }
    strcpy(employee_obj->company, company);

    employee_obj->department = malloc(sizeof(char)*(strlen(department) + 1));
    if(employee_obj->department == NULL) {
        return NULL;
    }
    strcpy(employee_obj->department, department);
    
    employee_obj->salary = salary;
        
    employee_obj->get_contract = get_contract;
    
    // Changing base class interface to access derived class functions
    // person destructor pointing to employee destrutor
    person_obj->delete = delete_employee;

    return person_obj;
}

void get_contract(employee* const employee) {
    printf("I am working for %s in the %s department and receiving %d euros per month!\n",
           employee->company, employee->department, employee->salary);
}

void delete_employee(person* const person) {
    printf("I, %s %s, got fired employee! (T_T)\n", person->first_name, person->last_name);
}

/*********************************************************************************************************/

boss* new_boss(const char* const first_name, const char* const last_name, const int age,
                     const char* const company, const char* const department, int payment) {

    // Calling base class construtor
    boss* boss_obj;
    person* person_obj = new_person(first_name, last_name, age);
    
    //allocating memory
    boss_obj = malloc(sizeof(boss));
    if (boss_obj == NULL) {
        person_obj->delete(person_obj);
        return NULL;
    }
    boss_obj->parent_object = person_obj; // pointing to parent object

    //initialising derived class members
    boss_obj->company = malloc(sizeof(char)*(strlen(company)+1));
    if(boss_obj->company== NULL) {
        return NULL;
    }
    strcpy(boss_obj->company, company);

    boss_obj->department = malloc(sizeof(char)*(strlen(department) + 1));
    if(boss_obj->department == NULL) {
        return NULL;
    }
    strcpy(boss_obj->department, department);
    
    boss_obj->payment = payment;
        
    boss_obj->offer_contract = offer_contract;
    
    // Changing base class interface to access derived class functions
    // person destructor pointing to boss destrutor
    person_obj->delete = delete_boss;

    return boss_obj;
}

void offer_contract(boss* const boss) {
    printf("You will be working for %s in the %s department and receive %d euros per month!\n",
           boss->company, boss->department, boss->payment);
}

void delete_boss(person* const person) {
    printf("Firing %s %s! He useless!\n", person->first_name, person->last_name);
}

int main() {
    person* person_obj = new_person("Tomas", "Carrasco", 23);
    person* employee_obj = new_employee(person_obj->first_name, person_obj->last_name, person_obj->age, "Nova Base", "Code Monkey", 1200);
    boss* boss_obj = new_boss(person_obj->first_name, person_obj->last_name, person_obj->age, "Nova Base", "Code Monkey", 1200);

    printf("\nPerson:\n");

    // displaying person info
    person_obj->display(person_obj);
    
    // getting person age
    printf("I am %d years old!\n", person_obj->get_age(person_obj));
    
    // writing person info in the persondata.txt file
    person_obj->write_to_file(person_obj, "person_data.txt");

    // delete the person object
    person_obj->delete(person_obj);
    person_obj = NULL;

    printf("\nEmployee:\n");

    // displaying employee info
    employee_obj->display(employee_obj);
    
    // getting employee age
    printf("I am %d years old!\n", employee_obj->get_age(employee_obj));
    
    // getting employee contract
    ((employee*) employee_obj->child_object)->get_contract(employee_obj->child_object);

    // writing employee info in the employee_data.txt file
    employee_obj->write_to_file(employee_obj, "employee_data.txt");

    // delete emplyoee object
    employee_obj->delete(employee_obj);
    employee_obj = NULL;

    printf("\nBoss:\n");

    // displaying boss info
    boss_obj->parent_object->display(boss_obj->parent_object);
    
    // getting boss age
    printf("I am %d years old!\n", boss_obj->parent_object->get_age(boss_obj->parent_object));
    
    // getting boss contract
    boss_obj->offer_contract(boss_obj);

    // writing boss info in the boss_data.txt file
    boss_obj->parent_object->write_to_file(boss_obj->parent_object, "boss_data.txt");

    // delete boss object
    boss_obj->parent_object->delete(boss_obj->parent_object);
    boss_obj = NULL;

    return 0;
}