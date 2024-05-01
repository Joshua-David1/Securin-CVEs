<img width="1677" alt="Screenshot 2024-05-01 at 3 21 17 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/0570d37e-cb67-4088-8e98-b01e2fb408a3"># Securin-CVEs
## Problem Statement
To develop a web application leveraging the CVE API to retrieve detailed information on individual CVEs or batches from the NVD.

## Stack

1. FrontEND - HTML,CSS and bootstrap.
2. BackEND - Flask
3. Database - Sqlite

### DATABASE

1. The database consists of 3 tables. CVE (This contains the list of all the CVEs and the fundamental metrics). Details (This contains a detailed description of a particular CVE). CPEMATCH (This contains the cvssMertics of a particular CVE - like cvssScore, impact_score etc).

### ENDPOINTS

1. /cves/list
2. /cves/<cve_id>
3. /update

#### /cves/list
1. This endpoint lists out all the CVEs which are available.

#### /cves/<cve_id>
1. This endpoint lists out the detailed description of a particular CVE.

#### /update
1. This endpoint is wrapped around a scheduler. It triggers every 1 hour as it extracts the data through CVE API and updates it in the database.

## Documentation

<img width="1671" alt="Screenshot 2024-05-01 at 3 07 45 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/4afa09c9-272a-4252-b4b0-f8799a2212f2">

1. By visiting the /cves/list endpoint, we'd be able to see all the available CVE's displayed. By default, a page would consist of 10 entries.
2. The total number of records available, the total number of pages available and the entries per page... all will be displayed in the UI.
3. When /cves/list endpoint is hit, it queries the CVE table for the list of CVEs available.
4. The CVE table would return all the CVEs data.

<img width="1677" alt="Screenshot 2024-05-01 at 3 21 17 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/612eba1c-6f23-4d2f-b001-203923b1d7ff">

5. When the 50 in the top right corner is clicked, each page would display 50 CVE entries.

<img width="1668" alt="Screenshot 2024-05-01 at 3 23 05 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/9aa3ffc3-7eab-4619-a3fc-667a589c68a7">

6. We can filter out the records based on the year the CVE was published. As seem from the above image, the CVEs published in the year 1990 are filtered out.

<img width="1668" alt="Screenshot 2024-05-01 at 3 26 39 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/1fe4e789-31d5-45ae-9b69-6aaab67bb936">
<img width="1675" alt="Screenshot 2024-05-01 at 3 27 20 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/74d50167-0d60-47ed-874c-2204bae0f3af">

7. Filteration can also be done by CVE-ID, BASE SCORE and Recently updated CVEs.
   
<img width="1680" alt="Screenshot 2024-05-01 at 3 29 41 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/95f6187e-f197-4eb3-9f6d-6a01ab6a4a01">

8. When the link of a particular CVE is clicked, a detailed description of the CVE could be viewed.






<img width="1675" alt="Screenshot 2024-05-01 at 3 27 20 PM" src="https://github.com/Joshua-David1/Securin-CVEs/assets/69303816/9ee5554e-6fff-4723-acf9-8a6ae1e43417">



