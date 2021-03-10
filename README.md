## IBP TEAM INTERNALS  
IBP Consoles:
https://aitrustorg1-ibp-console-console.aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud <br/>
Login: markparz@us.ibm.com <br/>
Password: TgM9zQYZhv8= <br/>

https://aitrustorg2-ibp-console-console.aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud <br/>
Login: markparz@us.ibm.com <br/>
Password: TgM9zQYZhv8= <br/>

The AITrust smart contract will need to installed/instantiated on one of these IBP environments. 

The IBP/identities folder has all the indentities needed to manage the fabric for Org's 1 and 2. 

The design spec: https://ibm.ent.box.com/notes/727314494492

Need to create a wallet & register a user 
cd into the server folder and run:

`npm install`
`npm start`

Open a new terminal and issue:

`node enrollAdmin.js`

## API REST
All REST APIs are documented via Swagger 
[Swagger UI](http://aitrust2-1abd866a65a6a73350903823fc77cd5f-0000.us-south.containers.appdomain.cloud/api-docs/#/)
