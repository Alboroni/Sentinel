# Introduction

#### Objectives

After completing this lab, you will be able to:

· Deploy Azure Sentinel as a platform for visualizing, investigating, and alerting on your customer's security big data

· Confidently use Sentinel to render your customer's visualized data truly actionable

· Respond to security incidents and Indicators of Compromise discovered with Sentinel

· Proactively hunt for misconfigurations and Indicators of Compromise with hunting queries

#### Scenario

In this technical workshop, attendees will analyze log data from a Pre-populated Sentinel workspace. You will not need (and won’t be able to use) your own Azure tenant or subscription. User names and passwords will be provided throughout. Please log on exactly as detailed, including the number that you have been assigned. **Failure to do so will result in potential problems for other lab participants.**

The Sentinel workspace(s) that you will be working with have been configured with multiple data sources, including Office 365, Azure Active Directory (AD) Sign-in logs, Azure AD Audit logs, and Windows Security Event logs. All Data connectors have been configured to forward all relevant data to the sample Sentinel workspace(s) you’ll be working with. Several vulnerabilities have also been configured in these data source environments.

#### Lab technology
In this technical workshop, you will not need to access any IaaS or any other machines directly. Instead, you will use your own computer to access a preconfigured lab in Azure.

#### User accounts <br>
To access the azure lab, you will navigate to:https://portal.azure.com<br>
You will then logon with the following account:
Admin**XX**@sentinellab.xyz, where “XX” is the number you have been assigned at the start of class.<br>
For example, if I was assigned number 47, my username would be user**47**@sentinellab.xyz<br>
Username: **AdminXX@sentinellab.xyz**<br>
Password: **Assigned by instructor**

**This is the account you will use except where otherwise specified (as in Exercise 2).**

**Important Note**: Because data changes rapidly, throughout this lab your results may be slightly different than the examples given throughout this lab guide. The guide is meant to be illustrative; slight differences in data are not a problem.

**Important Note 2**: All exercises in this lab should be completed using an InPrivate (Edge) or Incognito (Chrome) browser session. This will ensure that your Microsoft or other credentials do not interfere.
# Exercise 1: Review Azure Sentinel Data Connectors
In this exercise you will be reviewing the data connectors of Azure Sentinel to confirm that data is already being collected in the Sentinel Workspace.  Data connectors are critical to a setup of Azure Sentinel so that data can flow into the workspace.  To save time, these data connectors have been configured in advance.<br>
**Task 1: Log on to Azure and Navigate to Sentinel**<br>
In this task, you will log into the Azure portal and navigate to Sentinel.
1.	In a browser, navigate to https://portal.azure.com.

2.	Enter the account information:
Username: **AdminXX@sentinellab.xyz** (where “XX” is the number you have been assigned at the start of class)<br>
Password: **Assigned by instructor**

3.	This brings you to the Azure Home. In the box at the top, search for **Sentinel**.
4.	In the results, click on **Azure Sentinel**.


![alt text](screenshots/portal2_new.PNG)<br><br>

5.	Click **briandel**, which is the name of the Sentinel Workspace.

![alt text](screenshots/workspace.PNG)<br><br>

6.	In the Navigation bar, select **Data Connectors**

![alt text](screenshots/connectors.PNG)<br><br>

7.	Locate the data connectors **Azure Active Directory** and **Security Events** and confirm that the Last log received time is within the last 30 minutes.
8.	Click the **Azure Active Directory** connector and Click **Open connector page**
9.	Confirm the status of the connector as **Connected**

![alt text](screenshots/AAD.PNG)<br><br>

10.	Confirm that there has been recent data received

![alt text](screenshots/data_ingested.PNG)<br><br>

11. press **next steps** tab on the top of the page and discover sample quires, if you scroll down you will find  out-off-the-box analytics rules that can be enabled with this data source

![alt text](screenshots/next_step.png)<br><br>


### Continue with the next lab
LAB 02 -Setup Alerts (Analytics) and Respond to Cases in Azure Sentinel, click <a href="LAB02" target="_blank">here</a>
