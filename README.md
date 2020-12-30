# Overview of Fork
This fork has been done by Abdul Rabbani, an employee at Microsoft.
The contributing code interacts with a GCP backend service.
It allows users to add/remove instance groups to/from backend services,
check instance health, take snapshots of your infrastructure, amongst other use
cases (which will be added here).

Since this is a project which was started by a Microsoft employee,
Microsoft's code of conduct must be present: https://opensource.microsoft.com/codeofconduct

# How to Make the Code Work

All contributions can be found in current_contribution.
To make the code work a few things need to be done.

## Infrastructure
A load balancer must be created with 2 instances groups, with at least 1 instance
in each. The load balancer needs to have a health check.

## Service Account
A service account will be needed for the authentication.
In the future this will be dropped and whatever auth method the base
repo uses will be picked up. But until then, a service account will be needed,
and a `gcp_cred.json` file will need to created. Instructions can be found in
`current_contribution/gcp_cred.md`.

# To Do
The code outline needs to be integrated to the standard provided by GCP.
Some open items

1. Make the code work
2. Make the Unit test work
3. Integrate the current method of authentication.
4. Get in contact with someone who maintains the code body.
5. Ask for guidance
6. Create playbook.
