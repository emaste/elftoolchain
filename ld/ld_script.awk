# $Id$

BEGIN {
    split(ARGV[1], s, ".");
    sub(".*/", "", s[1]);
    printf "const char *%s = ", s[1];
}

{
    printf "\"";
    gsub("\"", "\\\"");
    printf "%s\\n\"\n", $0;
}

END {
    print ";";
}
