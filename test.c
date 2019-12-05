int someLibraryFunction();

int foo()
{
    someLibraryFunction();
    return 7;
}

int bar()
{
    return foo() + 3;
}

int main()
{
    foo();
    bar();
}