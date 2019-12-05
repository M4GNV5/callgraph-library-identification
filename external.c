int mostUsedLibraryFunction()
{
    return 42;
}

int yetAnotherLibraryFunction()
{
    mostUsedLibraryFunction();
    return 1337;
}

int someOtherLibraryFunction()
{
    yetAnotherLibraryFunction();
    return mostUsedLibraryFunction();
}

int someLibraryFunction()
{
    mostUsedLibraryFunction();
    return someOtherLibraryFunction();
}