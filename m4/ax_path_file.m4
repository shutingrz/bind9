#
# Subroutine for searching for an ordinary file (e.g., a stylesheet)
# in a number of directories:
#
#   AX_PATH_FILE(VARIABLE, FILENAME, DIRECTORIES)
#
# If the file FILENAME is found in one of the DIRECTORIES, the shell
# variable VARIABLE is defined to its absolute pathname.  Otherwise,
# it is set to FILENAME, with no directory prefix (that's not terribly
# useful, but looks less confusing in substitutions than leaving it
# empty).  The variable VARIABLE will be substituted into output files.
#

AC_DEFUN([AX_PATH_FILE], [
$1=""
AC_MSG_CHECKING(for $2)
for d in $3
do
        f=$d/$2
        if test -f $f
        then
                $1=$f
                AC_MSG_RESULT($f)
                break
        fi
done
if test "X[$]$1" = "X"
then
        AC_MSG_RESULT("not found");
        $1=$2
fi
AC_SUBST($1)
])
