#
#        _| _ __|_           Script:  '2.08 Workflows.ps1'
#       (_|(_|_)| ) .        Author:  Paul 'Dash'
#      t r a i n i n g       Contact: paul@dash.training
#                            Created: 2021-09-29
#



# TODO: Label this as Windows PowerShell 5.1-only legacy content and provide a current PowerShell 7 comparison using ForEach-Object -Parallel or thread jobs.
# TODO: Add setup/cleanup for suspended workflow jobs so the demo is repeatable and does not leave jobs behind.
# PARALLELISM
#################################################
workflow ParallelDemo {
    parallel {
        Get-Service
        Get-Process
    }
}

ParallelDemo # notice how objects will be returned in a mixed order


# SUSPENDING
#################################################
workflow SuspendDemo {
    sequence {
        Get-Service -Name spooler
        Suspend-Workflow
        Get-Process -Name spoolsv
    }
}

SuspendDemo # workflow suspends in middle of execution
            # so the Get-Service output is returned
            # along with an object that represents a JOB...
# ...which you can list
Get-Job -Newest 1 -OutVariable WorkflowJob
# you can also resume running from the point where it was suspended
Resume-Job -Job $WorkflowJob
Get-Job -Id $WorkflowJob.Id
# to get the result, you have to ask for it
Receive-Job -Id $WorkflowJob.Id


# NOT WITHOUT PROBLEMS
#################################################

workflow ScopeDemo {
    $Name = 'Paul'
    Write-Host "Hello $Name"
}
ScopeDemo
# PROBLEM:    availability of certain commands
#             like the Write-Host which can't be used in WWF


# SOLUTION:   wrap them up in an InlineScript
workflow ScopeDemo {
    $Name = 'Paul'
    InlineScript {
        Write-Host "Hello $Name"
    }
}
ScopeDemo
# PROBLEM:    InlineScript launches separate PowerShell process
#             which doesn't have access to the Name in WWF memory


# SOLUTION:   put the Name in the InlineScript or reference it using $Using:
workflow ScopeDemo {
    $Name = 'Paul'
    InlineScript {
        Write-Host "Hello $Using:Name"
    }
}
ScopeDemo
# But at this point you may just be better off running the whole thing as a remote PowerShell script
