#!/bin/bash

# Test the top level arcade script.
# This will create several scripts and check to see that the correct one was executed.
# It modifies the created scripts to cause failures to make sure the arcade script is
# handling the failures properly.

setup_only='f'
if [ -n "$1" -a "$1" = '-s' ]; then
    setup_only=t
    shift
fi

if [ -z "$1" ] ; then
    echo "Test the arcade program itself."
    echo "Usage: $0 <arcade_root>"
    exit
fi
root="$1"
cd $root

test_scripts="tvb tvb.pl tvb.py tvb.sh tvb-veritable.py"

# Safety net
for script in ${test_scripts}; do
    if [ -e "libexec/${script}" ]; then
	echo "Oops: Script already exists: libexec/${script}"
	exit
    fi
done

# Create the test scripts
for script in ${test_scripts}; do
    cat > libexec/${script} <<EOF
#!/bin/sh

echo "Script: '\$0'"
echo "Args: \$@"
EOF
    chmod +x "libexec/${script}"

done

# Stop right here with the setup completed.
[ $setup_only = 't' ] && exit

# Run a test. Pass in the expected result command.
runtest() {
    expected="$1"
    # Note: All echo commands in this function must be sent to stderr or it will blow up the function.
    # Except for the actual return values.
    echo "Expected: ${expected}" 1>&2
    # Run the script and capture its output.
    result=$(bin/arcade tvb veritable 2>&1)
    # echo "# Result: '${result}'" 1>&2
    # Check for specific conditions.
    usage=$(echo "${result}" | grep -e '^usage:' | awk '{print $1}')
    arcade=$(echo "${result}" | grep -e '^.*arcade:' | awk '{print $1}')
    script=$(echo "${result}"  | grep -e '^Script' | awk '{print $2}')
    echo "Script returned: ${usage}${script}${arcade}" 1>&2
    if [ -n "${usage}" ] && [ "${expected}" = 'usage:' ]; then
	# Script returned a 'usage:" line.
	echo "Result: [OK]" 1>&2
	echo 1
    elif [ -n "${arcade}" ] && [ "${expected}" = 'arcade:' ]; then
	# Script returned an 'arcade:" line.
	echo "Result: [OK]" 1>&2
	echo 1
    elif [ -n "${script}" ] && [ "${script}" = "'${expected}'" ]; then
	# Script returned the expected sub command.
	echo "Result: [OK]" 1>&2
	echo 1
    else
	# Script didn't return the expected value.
	echo "Result: [FAIL]" 1>&2
	echo 0
    fi
}

# The tests.
pass=0
count=0

# Now remove exe bit from 'tvb.pl'.
echo "# Catch multiple scripts.\n# Currently:"
chmod -x "${root}/libexec/tvb.pl"
ls libexec/tvb*
ret=$(runtest 'arcade:')
rm -f "${root}/libexec/tvb.pl"
pass=$((pass + $ret))
count=$((count + 1))

# Remove executable permission from 'tvb'.
echo "# Checking for primary with extension.\n# Currently:"
rm -f "${root}/libexec/tvb.sh" "${root}/libexec/tvb.pl" "${root}/libexec/tvb"
ls libexec/tvb*
ret=$(runtest "${root}/libexec/tvb.py")
pass=$((pass + $ret))
count=$((count + 1))

# Check for base command.
echo "# Checking for default script 'tvb'\n# Currently:"
ls libexec/tvb*
mv "${root}/libexec/tvb.py" "${root}/libexec/tvb"
ret=$(runtest "${root}/libexec/tvb")
pass=$((pass + $ret))
count=$((count + 1))

# Remove executable permission from 'tvb'.
echo "# Catch failure message if default is not executable.\n# Currently:"
chmod -x "${root}/libexec/tvb"
ls libexec/tvb*
ret=$(runtest "arcade:")
rm -f "${root}/libexec/tvb"
pass=$((pass + $ret))
count=$((count + 1))

# Now remove the entire script 'tvb' and make 2 others not executable.
echo "# Checking combo scripts.\n# Currently:"
rm -f "${root}/libexec/tvb"
ls libexec/tvb*
ret=$(runtest "${root}/libexec/tvb-veritable.py")
pass=$((pass + $ret))
count=$((count + 1))

result="Success"
failed=$(($count - $pass))
[ ${failed} -gt 0 ] && result="Failed"
echo "# ${result}: $pass test(s) passed, $failed test(s) failed."

# Cleanup
for script in ${test_scripts}; do
    rm -f "libexec/${script}"
done
