#!/bin/bash

# Files (not deleted) in the index
files=$(git diff-index --name-status | grep -v ^D | cut -c3-)
if [ "$files" != "" ]
then
  for f in $files
  do
    if [[ "$f" =~ [.](conf|json|log|properties|sh|txt|cfg|yml|sql|py)$ ]]
    then
      # Add a linebreak to the file if it doesn't have one
      if [ "$(tail -c1 $f)" != '\n' ]
      then
        echo >> $f
        git add $f
      fi

      # Remove trailing whitespace if it exists
      if grep -q "[[:blank:]]$" $f
      then
        sed -i "" -e $'s/[ \t]*$//g' $f
        git add $f
      fi
    fi
  done
fi

