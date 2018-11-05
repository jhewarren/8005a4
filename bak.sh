#!/bin/bash

AST='c8505/a4'
FDT=`date +%Y%m%d%H%M`
DRV=/Volumes/bcit/active

zip _bak/$FDT.zip *
cp _bak/$FDT.zip $DRV/$AST/_bak/ && rm _bak/*.zip
