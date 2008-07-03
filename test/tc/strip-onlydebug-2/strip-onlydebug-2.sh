inittest strip-onlydebug-2 tc/strip-onlydebug-2
extshar ${TESTDIR}
extshar ${RLTDIR}
runcmd "../strip --only-keep-debug -o elfcopy.1 elfcopy" work true
rundiff true
