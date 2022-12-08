#!/bin/bash


test_scripts=''

seed_script() {
    cat > libexec/$1 <<EOF
#!/usr/bin/env python3

from arclib import grv

conf = grv.configDict()
$2
print(conf)
EOF
    chmod +x "libexec/$1"
    test_scripts="${test_scripts} $1"
}

# The tests.
pass=0
count=0

echo -n "Test get_bail() abort: "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
print ('Five: ', conf.get_bail('five', 'No five'))
"
result=$(bin/arcade ${test_script} 2>/dev/null)
if [ $? != 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test get_bail() found: "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
conf.five = 5
print ('Five: ', conf.get_bail('five', 'No five'))
if conf.five != 5:
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test get(): "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
if conf.get('three') != 'Three':
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test get() of missing value: "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
five = conf.get('five')
if five != '':
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test alt(): "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
five = conf.alt('five', 5)
if five != 5:
    print(f'five = ', five)
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test alt_set(): "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
five = conf.alt_set('five', 'Five')
if five != 'Five':
    print(f'five = ', five)
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi


echo -n "Test get_none(): "
count=$((count + 1))
test_script="lib-grv-test${count}"
seed_script ${test_script} "conf['one'] = 1
conf['two'] = 'Two'
conf['four'] = 4
conf['three'] = 'Three'
conf.alt_set('five', 'Five')
five = conf.get_none('five', 'Five')
if five != 'Five':
    exit(1)
"
result=$(bin/arcade ${test_script} 2>&1)
if [ $? = 0 ]; then
    echo "Result: [OK]"
    pass=$((pass + 1))
else
    echo "Result: [FAIL]"
fi



# Print the result of all the tests.
result="Success"
failed=$(($count - $pass))
[ ${failed} -gt 0 ] && result="Failed"
echo "# ${result}: $pass test(s) passed, $failed test(s) failed."


for script in ${test_scripts}; do
    rm -f "libexec/${script}"
done
