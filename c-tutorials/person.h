#include <stdio.h>
#include <stdlib.h>

typedef struct _person person;

//declaration of pointers to functions
typedef void (*display_func)(person*);                      // This creates a type, named display_func for a pointer
typedef void (*write_to_file_func)(person*, const char*);   // to a function that takes a single pointer to person argument
typedef void (*delete_func)(person*);                       // and returns void
typedef int (*get_age_func)(person*);

/**
 * \note In C all the members are by default public.
 *       We can achieve the data hiding (private members), but that method is tricky.
 *       For simplification of this article we are considering the data members public only.
 */
typedef struct _person {
    // attributes
    void* child_object; // used for person to access childs
    char* first_name;
    char* last_name;
    int age;

    // interface for function
    display_func display;
    get_age_func get_age;
    write_to_file_func write_to_file;
    delete_func delete;
} person;

person* new_person(const char* const first_name, const char* const last_name, const int age);
int get_person_age(person* const person);
void display_person_info(person* const person);
void write_person_to_file(person* const person, const char* file_name);
void delete_person(person* const person);

/*********************************************************************************************************/

typedef struct _employee employee;

typedef void (*get_contract_func)(employee*);

/**
 * \note Interface for this object is in the base object since all functions are virtual.
 */
typedef struct _employee {
    char* department;
    char* company;
    int salary;

    // Add interface here for any employee specific functions
    get_contract_func get_contract;
} employee;

person* new_employee(const char* const first_name, const char* const last_name, const int age, const char* const department, const char* const company, const int salary);
void delete_employee(person* const person);
void get_contract(employee* const employee);

/*********************************************************************************************************/

typedef struct _boss boss;

typedef void (*offer_contract_func)(boss*);

/**
 * \note Interface for this object is in the base object since all functions are virtual.
 * 
 * 
 */
typedef struct _boss {
    person* parent_object; // used for boss to access parent
    char* department;
    char* company;
    int payment;

    // Add interface here for any boss specific functions
    offer_contract_func offer_contract;
} boss;

boss* new_boss(const char* const first_name, const char* const last_name, const int age, const char* const department, const char* const company, const int payment);
void delete_boss(person* const person);
void offer_contract(boss* const boss);