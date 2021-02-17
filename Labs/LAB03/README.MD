## Exercise 3: Proactively Investigate Potential Threats, Misconfigurations, and Suspicious Activities Visually 
In this exercise, you will learn how to access Azure Sentinel and how to use a Workbook to view data visually. You will also learn how to examine the underlying Kusto queries, and to change them.
For this lab, Data connectors have already been added and appropriately configured as necessary.
.<br>

## Task 1: Log on to Azure and Navigate to Sentinel
In this task, you will log into the Azure portal and navigate to Sentinel.
1.	In a browser, navigate to https://portal.azure.com.

2.	Enter the account information:<br>
Username: **AdminXX@sentinellab.xyz** (where “XX” is the number you have been assigned at the start of class)<br>
Password: **Ask the trainer**<br>

3.	This brings you to the Azure Home. In the box at the top, search for **Sentinel**.
4.	In the results, click on **Azure Sentinel**
![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB01/screenshots/portal2.PNG
)<br><br>
6.	Click **briandel**, which is the name of the Sentinel Workspace.
![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB01/screenshots/workspace.PNG
)<br><br>

7.	Take a moment to examine the Sentinel **Overview** page. This page gives you a bird’s eye view of your estate’s data.<br>

## Task 2: Navigate the Overview Page and Understand Basic Kusto Queries

1. Look closely at the pane entitled **Events and alerts over time**. This pane provides a bar graph representing alerts, Windows Firewall Events, Security Events, Performance data, and other data that has been recently gathered.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/evetns.PNG
)<br><br>

2.	Click on **WindowsFirewall** off to the right.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/FW.PNG
)<br><br>

3.	You may encounter a **Welcome to Log Analytics** screen. If so, click **Get Started**. If not, simply continue with the next step.
4.	This opens up the **Logs** window and also demonstrates a critical point to understand. Azure Log Analytics (and the Kusto Query Language) forms a large portion of the platform upon which Azure Sentinel has been built.
5.	Once the query (“WindowsFirewall”) finishes, examine the data.
6.	Click one of the chevrons on the left to inspect a data element as in the example below (your data will be different).

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/FW_Events.PNG
)<br><br>

7.	In keeping with this simple query, this piece of data in the example above tells a simple story. In the example here, the machine DC04.ad.briandel.ca sent (through the Firewall) a UDP packet to 10.0.0.4 over Port 59,121. In itself, it is not terribly interesting. But in aggregate or as part of an investigation, Kusto queries like this can provide critical data as we shall see.
8.	Return to the Sentinel Overview page by clicking **Azure Sentinel – Overview** at the top.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/menu.PNG
)<br><br>

9.	This query is slightly more complex and will look something like this (the date and time fields will be different):

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/securityevents1.PNG
)<br><br>

10. This query is slightly more complex and will look something like this

```powershell
union SecurityEvent
```

11.	This query is asking for a **SecurityEvent** (from a Windows security log) during a specified date and time.
12.	Click on one of the chevrons, preferably for an **AccountType** of **User** and not a built-in account like NT AUTHORITY.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/Atype.PNG
)<br><br>

In this above example, the administrator account has failed to log on. This could be very telling as an early indicator of attack. Why is someone logging on (and failing) using the administrator account?<br>
Your data will look different than the example above.

12.	Click *Azure Sentinel – Overview** to return to the Sentinel Overview page.

## Task 3: Utilize Workbooks to Proactively Investigate Potential Threats, Misconfigurations, and Suspicious Activities**<br>

**Step 1**: Learn to navigate the Workbooks frame<br>

In this task, you will learn to proactively investigate using Sentinel Dashboards. Sentinel Workbooks provide visualized data from your connected data sources to help render them proactively actionable.
1.	From the Sentinel Overview page, click on Workbooks.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/workbookMenu.png
)<br><br>

2. On the next blade that appears, click Templates.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/workbooktemplate1.png
)<br><br>

3.	Take a moment to browse the list of built-in Workbooks such as **Azure Activity, Azure AD Sign-in logs, Office 365**, and third-party Workbooks for products from vendors like Symantec and Palo Alto. It is important to understand that **Workbook** are typically used with **Data connectors**. In fact, when you add a Data connector, you typically receive a **Recommended Workbook**, as in this example:

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/recoworkbooks.png
)<br><br>

4. Click on **Insecure Protocols**. In the lower right-hand corner, click View template in order to bring up the workbook.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/insecure_template.png)<br>


5. The **Insecure Protocols** workspace visually represents Security log data from on-premise or IaaS Active Directory Domain Controllers as well as Legacy Authentications taking place against Azure AD. Specifically, it represents data detailing which insecure protocols are currently in use and their data flows throughout the estate.


6. In the upper left-hand corner, set the TimeRange to last 90 days and ensure workspace is set to **briandel**

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/timerange.png)<br>


7.  Take a moment to browse the workbook. This workbook addresses the problem of organizations that wish to remove insecure protocols (like NTLMv1, SMB1, wDigest and weak Kerberos ciphers) but are unable to do so for fear of breaking critical business systems. They need to remediate the sources before they can disable the protocols. And for that they need data visualization.<br>

**Step 2**: Dive deeper in the Insecure Protocols Workbook to Investigate Security Data
1.	Let’s take a look at the overview graph titled **Summary of Insecure Protocols**.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/global_insecure.png
)<br><br>


3.	We can look into to the Insecure LDAP section of the page (press on the **LDAP Tab**) for more insightful data representations.<br>

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/unsignedLDAP.png
)<br><br>


4.	In the LDAP tab, note that by clicking on an account on the left, you can view more details.

**Step 3**: Delve deeper in the Data Represented in the Workbook

1.	Sometimes we will need to assist our customers in delving deeper into a particular data set or sets. In order to do that, we will often want to drill down closer to the actual data collected by Sentinel (Log Analytics on the back end). 
2.	Click on the **Azure Sentinel** at the top of the page



3.	Click on **Logs**

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/workbooklog.PNG)
<br><br>

4.	Let’s delve deeper into Unsigned LDAP Traffic using a query that is doing some extractions as well as RegEx matching to put the data in an acceptable format. 
5.	For example, maybe we need to know the Domain Controller being targeted by the Insecure LDAP binds. We can easily do that in the following steps.
6.	In the query window, copy the following query:

```powershell
Event
 | where EventID == 2889 
 | project ParameterXml, DomainController=Computer , TimeGenerated, EventID 
 | parse ParameterXml with * "<Param>" IPAddress ":" *
 | parse ParameterXml with * "><Param>" Account "</" *
 | parse kind = regex ParameterXml with * "</Param><Param>" * "</Param><Param>" BindingType "</Param>"
 | project DomainController  , TimeGenerated, Account, IPAddress  
```
And click **Run**

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/workbook_script.png
)<br><br>


In the output, Click one of the chevrons to the left side of the screen in order to examine one of these logs.

7.	This type of data can help fill in the missing pieces to our story. Depending on which log you clicked, you can gain the missing information. In the example below, we see that victim7 made an Insecure LDAP bind from IP 10.1.0.4 and against DC04. Your data will look different.

![alt text](https://raw.githubusercontent.com/alboroni/Sentinel/master/Labs/LAB03/screenshots/workbook_results1.png
)<br><br>



### Continue with the next lab
LAB 04 - Proactively Investigate Potential Threats, Misconfigurations, and Suspicious Activities with KQL Queries , click <a href="https://github.com/alboroni/Sentinel/tree/master/Labs/LAB04" target="_blank">here</a>