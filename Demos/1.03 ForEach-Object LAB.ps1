# 1. Run this line to save a value to a variable.
# TODO: Create exercise folders under a dedicated temporary path and include cleanup so reruns do not depend on or modify the learner's current directory.
$ComputerName = 'localhost'

# 2. Use Get-Member to inspect the System.String object that is now in the variable.
#    Notice the Chars parametrized property.
#    The index argument allows you to pick a letter from the string at that index. Indexing starts at 0.

# 3. Use the Chars parametrized property to pick the first letter of the string in $ComputerName.
#    For example, this will show the third letter of the string:
$ComputerName.Chars(2)



# SCENARIO: You need to organize your installation files by vendor but first
#           organize vendors into folders by the first letter of their name.

# 4. Run this line to save the list of software vendors to a variable. Add more if you feel like it.
$Vendors = 'Adobe','Microsoft','Google','Autodesk'

# 5. Using ForEach-Object, pick the first letter of each string in $Vendors.

# 6. Read help on Select-Object on how it can select unique objects.
#    Use it to create a unique list of the first letters.

# 7. Using ForEach-Object, create subdirectories named using the unique first letters of vendors.
#    You will need to use the New-Item cmdlet... a line to get you started is below:
New-Item -ItemType Directory -Name A






#################################################################################
# ANSWER
#
# #####
#
# ####
#
# ###
#
# ##
#
# #
#
$Vendors | ForEach-Object {$_.Chars(0)} | Select-Object -Unique |
ForEach-Object {New-Item -ItemType Directory -Name $_}


