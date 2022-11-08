#!/bin/bash

isPython=false
pythonFile=""
exitCode=0
while read -r line
do
    if [[ $line == "+++"* ]]; then
        if [[ $line == *".py" ]]; then
            isPython=true
            pythonFile=$line
        else
            isPython=false
        fi
    fi
    if $isPython && [[ $line == "+"*"ipdb"* ]]; then
        echo "Remove code breakpoint before committing:"
        echo $pythonFile
        exitCode=1
        break
    fi
done <<< "$(git status -v)"

exit $exitCode
