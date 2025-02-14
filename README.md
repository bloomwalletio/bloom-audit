# AuditOne Full Report

## [PenTest] DLL_hijacking

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/24](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/24)  
**Author:** [marcocarolasec](https://github.com/marcocarolasec)  
**Assignee:** [Tuditi](https://github.com/Tuditi)  
**Status:** Resolved

### Description

**Severity**

High

**Where**

Bloom.exe

**Impact**

Malicious code execution: The vulnerability allows a local attacker to execute malicious code remotely. During the exploit it was demonstrated how an attacker can cause the system to load a malicious DLL from a specific location, which opens the door to a variety of attacks, such as the execution of unauthorized programs.

**Description**

A DLL Hijacking vulnerability affecting the DWriteCore.dll library has been detected on Windows systems. The vulnerability lies in the way the operating system loads dynamic-link libraries (DLLs) when an application attempts to access specific functions. In this case, the vulnerability enables a local attacker to remotely execute malicious code by exploiting a specific path where the system tries to load the DLL.

---

Vulnerability Details:

• Vulnerable DLL Path: C:\Users\User\AppData\Local\Microsoft\WindowsApps\DWriteCore.dll

---

**Evidence of Affected DLLs:**

During exploration and analysis, it has been determined that other DLLs may be susceptible to this type of attack, especially those the system attempts to load from similar pathways. This broadens the vulnerability's scope and increases its potential impact on the system.

![dddddd](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/e284b633-bd89-4525-867e-ad05f116ef98)

![zzZZZ](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/804c3bb7-2c35-498a-86db-3dacfa20d188)

**Proof of Concept:**

To demonstrate the exploitation of this vulnerability, a proof of concept can be conducted by executing the calculator program (calc.exe). By manipulating the DWriteCore.dll in the mentioned path, an attacker can trick the system into loading it from that location instead of the legitimate DLL. Once loaded, the malicious DLL can execute arbitrary code, such as the calculator, thus demonstrating the successful exploitation of the vulnerability.

![imaaaaaage](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/8894a8d1-2585-439e-8535-5f6dbc07f3d6)

![dddddd](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/f2e9426f-32af-4cc9-a3ed-49e02b4bc9ab)

![imaaaaaaage](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/a10675f7-5349-49a1-894c-09c25c369dfa)

![2024-02-22 16_54_37-192 168 0 20 - Conexión a Escritorio remoto](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/61bc2e91-4632-4900-bc45-a64d5609c6e5)

![2024-02-22 16_57_06-192 168 0 20 - Conexión a Escritorio remoto](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/1297bdbb-9dd0-48be-9361-2ad32111cd08)

It is important to note that this vulnerability can be exploited by local attackers without the need for administrator privileges, which increases its criticality.

The user "asier" has full permissions (F), which means that he has full control over the folder and its contents. This includes the ability to read, write, modify, delete and change permissions on files and subfolders within the mentioned folder.

Since "asier" has full permissions (F) on the folder and its child items (CI), it has the authority to perform the following actions:

![2024-02-22 16_33_11-192 168 0 20 - Conexión a Escritorio remoto](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/a505a993-9bfb-4a79-916b-5ec7ba35196a)

**Recommendations to fix**

Preventing and mitigating DLL hijacking vulnerability requires a combination of secure development practices, proper system configurations, and security awareness among end-users. Below are the recommended strategies to prevent and mitigate risks associated with DLL hijacking:

- Secure Development:
  Software developers should adopt secure development practices that include accurately specifying the location of all DLLs used by an application. Avoiding the use of Windows' default DLL search protocol and specifying full paths for necessary DLLs is critical.

- Library Loading Auditing and Restriction:
  Conducting periodic system audits using tools like PowerUp can help detect and address DLL hijacking attempts. Additionally, it's advisable to restrict library loading to local DLLs and avoid loading remote DLLs, especially from untrusted locations.

- Execution Prevention:
  Employing application control solutions to identify and block potentially malicious software running via DLL hijacking is crucial. These solutions can apply additional restrictions to prevent the execution of unauthorized DLLs.

**Additional context**

Below is a list of all potentially exploitable DLLs.

- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Program Files\Bloom\WINSTA.dll
- C:\Program Files\Bloom\KBDUK.DLL
- C:\Program Files\Bloom\Wldp.dll
- C:\Program Files\Bloom\DPAPI.dll
- C:\Program Files\Bloom\CRYPTBASE.dll
- C:\Program Files\Bloom\profapi.dll
- C:\Program Files\Bloom\WTSAPI32.dll
- C:\Program Files\Bloom\mscms.dll
- C:\Program Files\Bloom\ColorAdapterClient.dll
- C:\Program Files\Bloom\rdpendp.dll
- C:\Program Files\Bloom\dwmapi.dll
- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\OLEACC.dll
- C:\Program Files\Bloom\OLEACCRC.DLL
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Program Files\Bloom\MSASN1.dll
- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Program Files\Bloom\CRYPTSP.dll
- C:\Program Files\Bloom\dxgi.dll
- C:\Program Files\Bloom\Wldp.dll
- C:\Program Files\Bloom\WINSTA.dll
- C:\Program Files\Bloom\KBDUK.DLL
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\d3d10warp.dll
- C:\Program Files\Bloom\CRYPTBASE.DLL
- C:\Program Files\Bloom\mf.dll
- C:\Program Files\Bloom\mfplat.dll
- C:\Program Files\Bloom\RTWorkQ.DLL
- C:\Program Files\Bloom\dwmapi.dll
- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Users\User\AppData\Local\Temp\CRYPTBASE.DLL
- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Program Files\Bloom\CRYPTBASE.DLL
- C:\Program Files\Bloom\DWriteCore.dll
- C:\Windows\System32\DWriteCore.dll
- C:\Windows\System\DWriteCore.dll
- C:\Windows\DWriteCore.dll
- C:\Program Files\Bloom\DWriteCore.dll
- C:\Users\User\AppData\Local\Programs\Python\Python38\Scripts\DWriteCore.dll
- C:\Users\User\AppData\Local\Programs\Python\Python38\DWriteCore.dll
- C:\Users\User\AppData\Local\Microsoft\WindowsApps\DWriteCore.dll
- C:\Users\User\.dotnet\tools\DWriteCore.dll
- C:\Program Files\Bloom\dbghelp.dll
- C:\Program Files\Bloom\WINMM.dll
- C:\Program Files\Bloom\IPHLPAPI.DLL
- C:\Program Files\Bloom\USERENV.dll
- C:\Program Files\Bloom\VERSION.dll
- C:\Program Files\Bloom\DWrite.dll
- C:\Program Files\Bloom\Secur32.dll
- C:\Program Files\Bloom\WINHTTP.dll
- C:\Program Files\Bloom\dhcpcsvc.DLL
- C:\Program Files\Bloom\SSPICLI.DLL
- C:\Program Files\Bloom\CRYPTBASE.DLL

**Conclusion**

A configuration for signing the DLLs has been added to the application build step, although it does not solve the issue directly it follows secure development practices.
As we use Electron as a framework for building the application we also inherit possible vulnerabilities that could be on Chrome as Electron is Chromium-based, and particularly with this issue of DLL hijacking, Chromium security team posted why it is not part of their threat model so it also makes sense for us to follow the same.
[Why aren‘t physically-local attacks in Chrome’s threat model?](https://chromium.googlesource.com/chromium/src.git/+/master/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)

---

## Potential differences between the `tokenBalance` and `fiatBalance`

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/1](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/1)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/views/dashboard/buy-sell/components/TransakAccountPanel.svelte#L15-L20
https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/views/dashboard/buy-sell/components/TransakAccountPanel.svelte#L38-L39

**Impact**

incorrect `fiatBalance` due to missing of rounding feature.

**Description**

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/views/dashboard/buy-sell/components/TransakAccountPanel.svelte#L12-L20

```svelte
    let tokenBalance: string
    let fiatBalance: string

    function updateBalances(): void {
        const tokens = $selectedAccountTokens?.[$activeProfile.network.id]
        const networkBaseCoin: ITokenWithBalance = tokens?.baseCoin
        tokenBalance = formatTokenAmountBestMatch(networkBaseCoin.balance.total, networkBaseCoin.metadata)
        fiatBalance = formatCurrency(getFiatValueFromTokenAmount(networkBaseCoin.balance.total, networkBaseCoin))
    }
```

As shown in above code, the function `formatTokenAmountBestMatch` applied the necessary roundings and return the tokenBalance which is string int his case.

after that the fiatBlance is updated by calling the `formatCurrency`. This function takes the networkBaseCoin.balance.total whic was used previously to compute the tokenBalance .

The function `formatCurrency` is not used the conmputed tokenBalance to derive the fiatBalance.

**Recommendations to fix**

```svelte
    let tokenBalance: string
    let fiatBalance: string

    function updateBalances(): void {
        const tokens = $selectedAccountTokens?.[$activeProfile.network.id]
        const networkBaseCoin: ITokenWithBalance = tokens?.baseCoin
        tokenBalance = formatTokenAmountBestMatch(networkBaseCoin.balance.total, networkBaseCoin.metadata)

       /// audit
      covert the tokenBalance  to Bigint and use it in below function.

        fiatBalance = formatCurrency(getFiatValueFromTokenAmount(networkBaseCoin.balance.total, networkBaseCoin))
    }
```

**Conclusion**

While the displayed fiat balance is computed using the raw token amount instead of the rounded value (which is only used for display), this inconsistency does not affect actual transaction processing since the raw token amount is always used as the source of truth. A recommended improvement would be to convert the rounded token balance back to a numerical form for fiat conversion to ensure display consistency. However, because the raw values govern transaction logic, the issue is deemed low severity, impacting only user display and not fund control.

---

## Update the "electron-updater": "6.1.4" to latest

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/2](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/2)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [Tuditi](https://github.com/Tuditi)  
**Status:** Resolved

### Description

**Severity**

Low

**Where**

[Where the issue is found](https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/package.json#L42)

**Impact**

Latest fixes would be missed due to the old version.

**Description**

The "electron-updater": "6.1.4" is used in the packag.json would be bit old.

There are already update went in the electron side. it would be better to use the latest version to get the additional fixes and feature.

**Recommendations to fix**

We would suggest to use the latest stable version.

**Conclusion**

electron-updater was updated to 6.3.4

---

## Required comments about function behavior is missing.

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/3](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/3)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [MarkNerdi](https://github.com/MarkNerdi)  
**Status:** Partially resolved

### Description

**Severity**

informational

**Where**

All scripts

**Impact**

It would be challenging to update the any further fix.

**Description**

All the script has crucial functionality to function the wallet. In some places, we see the comments about function working.
Its not provided in all the places.

**Recommendations to fix**

We would suggest to add necessary natspec comments about the functions working.

**Conclusion**

We added more comments.

---

## [PenTest] Cleartext_PIN

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/23](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/23)  
**Author:** [marcocarolasec](https://github.com/marcocarolasec)  
**Assignee:** [Tuditi](https://github.com/Tuditi)  
**Status:** Resolved

### Description

**Severity**

Medium

**Where**

Bloom.exe (Windows)

**Impact**

By extracting the PIN, the wallet can be accessed and all movements and information stored inside can be viewed.

**Description**

The vulnerability lies in the way the bloom.exe application handles the storage of the wallet access PIN. Instead of using secure credential storage methods, the PIN is stored in clear text and base64-encrypted before being stored in the Windows Vault. This exposes the PIN to any malicious actor who can access the operating system.

1. Access the operating system where the bloom.exe application is installed.
2. Locate the Windows Vault where credentials are stored.
3. Search for the file or entry related to the bloom.exe application.
4. Extract and decode the base64 encoded credential to reveal the wallet access PIN.

The following proof of concept extracts the PIN via command line.

![2024-02-22 16_08_55-Credencial en texto claro docx - Word](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/e17cb915-c00e-4413-9e71-c00af9807f97)

![image](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/bc6e9471-b51f-45cb-8158-4f1f085a4dc9)

---

**Recommendations to fix**

- Patching and Updates: The bloom.exe application development team should address this vulnerability immediately and provide an update that implements a secure method for credential storage.
- Secure Encryption: It is recommended to use robust encryption algorithms and secure storage practices to protect sensitive information such as the wallet access PIN.
- Security Auditing: Conduct regular security audits to identify and remediate potential vulnerabilities in the application and its handling of sensitive data.

**Conclusion**

We added hashing functionality to the PIN code.

---

## TransakAccountPanel.svelte : undefined case is not handled correctly

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/4](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/4)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [MarkNerdi](https://github.com/MarkNerdi)  
**Status:** Resolved

### Description

**Severity**

Medium

**Where**

[Where the issue is found](https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/views/dashboard/buy-sell/components/TransakAccountPanel.svelte#L17)

**Impact**

Function behaves abnormally when it meet undefined case

**Description**

Function `updateBalances()` updates the token and fiat balance values.

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/views/dashboard/buy-sell/components/TransakAccountPanel.svelte#L15-L20

```svelte
    function updateBalances(): void {
        const tokens = $selectedAccountTokens?.[$activeProfile.network.id]
        const networkBaseCoin: ITokenWithBalance = tokens?.baseCoin --------->> if eithe baseCoin is not defined or updated, next lines would meet the undefined secnario.
        tokenBalance = formatTokenAmountBestMatch(networkBaseCoin.balance.total, networkBaseCoin.metadata)
        fiatBalance = formatCurrency(getFiatValueFromTokenAmount(networkBaseCoin.balance.total, networkBaseCoin))
    }
```

**Recommendations to fix**

Check the output from the line `const networkBaseCoin: ITokenWithBalance = tokens?.baseCoin`

if the `networkBaseCoin` is undefined, return the undefined and handle further.

**Conclusion**

Not a security issue but could crash the application. The fix was done by setting empty string as initial value for tokenBalance and fiatBalance and adding an early return if networkBaseCoin is a falsy value.

---

## windows.transak.loadURL is not using the Node's url.format method to load url

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/5](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/5)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [jeeanribeiro](https://github.com/jeeanribeiro)  
**Status:** Resolved

### Description

**Severity**

Medium

**Where**

[Where the issue is found](https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/lib/electron/managers/transak.manager.ts#L85-L86)

**Impact**

URL Validation: Manually constructing URLs increases the likelihood of introducing errors, such as missing or misplaced slashes, invalid characters, or incorrect encoding. This can lead to URLs that are not properly formatted or are invalid according to standards.

Inconsistent URL Handling: Different parts of the URL, such as the query parameters or fragments, may not be properly encoded or formatted consistently, leading to inconsistencies in URL handling across different parts of your codebase.

Security Vulnerabilities: Incorrectly constructed URLs may introduce security vulnerabilities such as injection attacks (e.g., XSS or SQL injection) if user-provided input is not properly sanitized and encoded.

Difficulty in Maintenance: Manually constructed URLs can be difficult to read, maintain, and debug, especially as the complexity of the URL and the number of parameters increase.

Compatibility Issues: URLs constructed manually may not be compatible with certain components or libraries that expect URLs to be in a specific format, leading to compatibility issues and potential bugs.

**Description**

Following function calls do the url construction and loading it.

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/lib/electron/managers/transak.manager.ts#L85-L86

```typescript
const url = this.getUrl(data);
void windows.transak.loadURL(url);
```

when we look at the `this.getUrl(data)` implementation, it manually constructs the url path as shown below.

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/lib/electron/managers/transak.manager.ts#L150-L155

```typescript
    private getUrl(data: ITransakWindowData): string {
        const { address, currency, service } = data
        const apiKey = process.env.TRANSAK_API_KEY

        return `${TRANSAK_WIDGET_URL}/?apiKey=${apiKey}&defaultFiatCurrency=${currency}&walletAddress=${address}&productsAvailed=${service}&cryptoCurrencyCode=IOTA&network=miota&themeColor=7C41C9&hideMenu=true`
    }
```

**Recommendations to fix**

we would suggest Node's url.format method which is standard to construct the url.

sample codes

```typescript
const url = require("url");

const TRANSAK_WIDGET_URL = "..."; // Replace '...' with the actual base URL
const apiKey = "..."; // Replace '...' with the actual API key
const currency = "..."; // Replace '...' with the actual default fiat currency
const address = "..."; // Replace '...' with the actual wallet address
const service = "..."; // Replace '...' with the actual product availed

const urlObject = {
  protocol: "https",
  hostname: TRANSAK_WIDGET_URL,
  pathname: "/",
  query: {
    apiKey: apiKey,
    defaultFiatCurrency: currency,
    walletAddress: address,
    productsAvailed: service,
    cryptoCurrencyCode: "IOTA",
    network: "miota",
    themeColor: "7C41C9",
    hideMenu: "true",
  },
};

const urlString = url.format(urlObject);
console.log(urlString);
```

**Conclusion**

We fixed by using the web native URL API. [URL -  Web APIs | MDN](https://developer.mozilla.org/en-US/docs/Web/API/URL)

---

## transak.manager.ts : Check valid pre-load path

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/6](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/6)  
**Author:** [aktech297](https://github.com/aktech297)  
**Assignee:** [jeeanribeiro](https://github.com/jeeanribeiro)  
**Status:** Resolved

### Description

**Severity**

Low

**Where**

https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/lib/electron/managers/transak.manager.ts#L11-L14

**Impact**

unexpected crash in the application while accessing the invalid path.
other security vulnerabilities if the path is corrupted.

**Description**

in `TransakManager` script, first, the path is preloaded as shown below.
https://github.com/bloomwalletio/bloom/blob/0a8c26f7df74686ae56ecad3762689e912004d58/packages/desktop/lib/electron/managers/transak.manager.ts#L11-L13

```typescript
    private preloadPath = app.isPackaged
        ? path.join(app.getAppPath(), '/public/build/transak.preload.js')
        : path.join(__dirname, 'transak.preload.js')
```

In the process of loading the path, it fetch the preload js path and create the path to pre-load.

After that, this path is used without any check or further input sanitation.

it could happen if the application did not get any permission or bug in the permission granting.

**Recommendations to fix**

validate the `preloadPath ` . If the path is NULL or undefined, return with error and handle it in the front end.

**Conclusion**

We added validations to preload file existence, file extension and event-based error handling in the front-end.

---

## [Transak] Exposure of Personal Information through GET URLs in Integration with Transak

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/7](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/7)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [jeeanribeiro](https://github.com/jeeanribeiro)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

Transak

**Impact**

Personal data, including names, email addresses, mobile numbers, dates of birth, and physical addresses, are being passed through GET URLs. This method of transmitting sensitive information is insecure because GET URLs can be easily intercepted by attackers in a Man-In-The-Middle (MITM) attack.

**Description**

The issue is belongs to **Transak**.

Our application, Bloom, integrates with Transak for facilitating transactions. However, there's a critical privacy and security issue with how personal information is transmitted to Transak. Personal data, including names, email addresses, mobile numbers, dates of birth, and physical addresses, are being passed through GET URLs. This method of transmitting sensitive information is insecure because GET URLs can be easily intercepted by attackers in a Man-In-The-Middle (MITM) attack. Additionally, URLs are often logged in server access logs and might be cached by browsers or intermediary devices, leading to unintended disclosure of personal information.

Example Transak Integration Document : https://docs.transak.com/docs/white-label-integration

```javascript
https://global-stg.transak.com/
?apiKey=<YOUR_API_KEY>
&themeColor=2575fc
&defaultPaymentMethod=credit_debit_card
&cryptoCurrencyCode=ETH
&fiatAmount=100
&fiatCurrency=GBP
&userData=%7B%22firstName%22%3A%22Satoshi%22%2C%22lastName%22%3A%22Nakamoto%22%2C%22email%22%3A%22satoshi.nakamoto%40transak.com%22%2C%22mobileNumber%22%3A%22%2B15417543010%22%2C%22dob%22%3A%221994-08-26%22%2C%22address%22%3A%7B%22addressLine1%22%3A%22170%20Pine%20St%22%2C%22addressLine2%22%3A%22San%20Francisco%22%2C%22city%22%3A%22San%20Francisco%22%2C%22state%22%3A%22CA%22%2C%22postCode%22%3A%2294111%22%2C%22countryCode%22%3A%22US%22%7D%7D
&walletAddress=0x123Ba4676Fb1E2f9Ge2921e8634570F9a42dC3e3
```

**Recommendations to fix**

Until the fully white-labeled API solution is available, it is imperative to transition to more secure methods of transmitting personal information. POST requests, which include sensitive data within the body of the request rather than the URL, should be used as an interim solution.

**Conclusion**

This is the default implementation of Transak and a full white-label solution is not yet available.

---

## [PenTest] Disclosure of User PIN Through Operating System Memory on Main Screen

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/8](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/8)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Acknowledged

### Description

**Severity**

Medium

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Impact**

The exposure of the PIN in the system's memory compromises the confidentiality and integrity of user authentication mechanisms. It poses a substantial risk of unauthorized access to user accounts, leading to potential misuse, financial loss, or breach of personal and sensitive information.

**Description**

The application is inadvertently exposing the user's Personal Identification Number (PIN) on the main screen through the operating system's memory. This vulnerability arises when the PIN, intended for securing user access and authentication, is stored or processed in a way that leaves it accessible in the system's memory. This could potentially allow unauthorized access to the PIN through memory dump analysis or other memory inspection techniques, posing a significant security risk.

**Proof Of Concept**

- Install application on the Windows Operating System.
- Import wallet and set pin on the screen.
- Logout from profile and enter the pin.
- Take a memory dump through Process Explorer (SysInternal).

![305703515-6239d8db-14bc-4ee6-8bdd-1b7c6be80121](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/244c693b-9fad-4cad-a0dc-b86fc2f0fe39)

- Create a full dump.
- Use strings.exe to dump strings from the memory dump.
- Pin can be seen from the dump.

![305703552-36471215-cdc6-4cb4-8b5e-983a6701405a](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/1df30deb-ba21-4eba-8bca-2de4198fcb80)

**Recommendations to fix**

Consider clearing overall sensitive variables after usage on the application.

**Conclusion**

The solution recommends mitigating the risk of exposing the user’s PIN in memory by nullifying sensitive variables after use, thereby reducing the window in which clear-text PINs are retained. While this approach may not guarantee that the garbage collector immediately frees the memory, it is considered a reasonable improvement given the current threat model. Additionally, an alternative approach of transmitting only a hashed PIN across the electron bridge—while has already been implemented. Overall, the PIN disclosure issue is acknowledged but is deemed an acceptable risk within the defined security framework.

---

## [Transak] "Download Recovery Kit Template" Returns Empty Data

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/9](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/9)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Invalid

### Description

**Severity**

High

**Where**

Transak

**CVSS**

[CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:H)

**Impact**

The primary consequence of this issue is the potential risk to data security and user confidence. Without access to a functional recovery kit template, users may resort to less secure methods of storing their recovery phrases, such as unencrypted digital notes or physical copies in insecure locations.

**Description**

The feature designed to allow users to download a recovery kit template from the "Recovery Phrase" section is currently malfunctioning, resulting in the download of an empty data file. This functionality is critical for users to securely store their recovery phrase, a key component in account recovery and securing user assets. The failure of this feature to provide the necessary data compromises user preparedness in securely backing up their account recovery information.

![305702916-04baeeda-7143-431a-8787-1d2f532587e2](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/aa4a966b-88c9-4495-b2e0-a7117b5fe920)

**Recommendations to fix**

Promptly investigate and rectify the underlying cause of the empty data file issue. Ensure thorough testing is conducted to prevent similar issues from occurring in the future.

**Conclusion**

The recovery kit template is a page to be printed and the data is to be manually filled by the user, using a pen or pencil.

---

## [PenTest] Integration of Electronegativity GitHub Action for Enhanced Electron Application Security

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/12](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/12)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [MarkNerdi](https://github.com/MarkNerdi)  
**Status:** Acknowledged

### Description

**Severity**

Informational

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N)

**Impact**

Without the integration of Electronegativity, the application is at a higher risk of shipping with security vulnerabilities and misconfigurations that could be exploited by attackers. These vulnerabilities can lead to issues such as unauthorized access, data leakage, and other security breaches, potentially compromising user data and trust in the application. By automating the identification of these issues, developers can address vulnerabilities early, reducing the risk of exploitation and enhancing the overall security posture of the application.

**Description**

The current Continuous Integration/Continuous Deployment (CI/CD) pipeline lacks a dedicated mechanism for identifying misconfigurations and security anti-patterns in Electron applications. Electronegativity is a tool designed to address this gap by scanning Electron applications for common misconfigurations and security vulnerabilities. Integrating Electronegativity as a GitHub Action within the CI/CD pipeline would automate the process of scanning and identifying potential security issues early in the development process. The action is configured to produce a GitHub compatible Static Analysis Results Interchange Format (SARIF) file, which can be uploaded to the repository's 'Code scanning alerts' section for easy tracking and resolution of identified issues.

**Recommendations to fix**

Implement the [Electronegativity](https://github.com/doyensec/electronegativity-action) GitHub Action in the project's CI/CD pipeline. Configure the action to scan the Electron application codebase during the CI process.

**Conclusion**

Electronegativity is no longer maintained.

---

## [PenTest] Clipboard Jacking in Recovery Phrase Entry Section

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/13](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/13)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

[PenTest]

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N
](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:N/A:N)

**Impact**

The primary risk of this vulnerability is the unauthorized access to and theft of sensitive user information. If attackers successfully intercept through infected computer, they could gain access to users' accounts, leading to potential loss of control over personal or financial data. This breach could result in financial theft, identity theft, and a significant loss of trust in the application's security measures.

**Description**

The "Enter Your Recovery Phrase" section of the application is currently susceptible to clipboard jacking attacks. Clipboard jacking, also known as clipboard hijacking, is a form of cyber attack where malicious scripts or applications monitor and potentially manipulate the contents of the clipboard. In this context, when users copy their recovery phrase from a digital note or document and paste it into the application, there's a risk that a malicious script could intercept or alter the clipboard contents. This vulnerability primarily arises due to the application not implementing defenses against such clipboard-based attacks, potentially allowing attackers to capture or change the recovery phrase without the user's knowledge.

![image](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/5673c31f-d239-407f-a0b9-dfeb33aea3e3)

**Recommendations to fix**

Implement measures to disable direct access to the clipboard for the recovery phrase entry section. Encourage manual entry of the recovery phrase to avoid clipboard-based vulnerabilities.

**Conclusion**

After careful consideration, we acknowledge that the clipboard jacking vulnerability in the "Enter Your Recovery Phrase" section is present. However, based on our current threat model and the low severity of this issue, we have determined that it does not warrant remediation at this time.

---

## [PenTest] Transmission of Username and Password in Clear Text

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/14](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/14)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Invalid

### Description

**Severity**

Low

**Where**

[PenTest]

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

**Impact**

Sending username and password information in clear text compromises the confidentiality of user credentials, making them vulnerable to interception by malicious actors.

**Description**

The application version 0.1.7, running on macOS version 14.1.1 with an x64 architecture, has been identified to transmit username and password credentials in clear text as part of the URL.

![image](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/cfc1c183-4618-4f38-b20e-b1b8d836583a)

**Recommendations to fix**

Transmit authentication tokens or credentials in HTTP headers instead of the URL to enhance security and prevent logging of sensitive information in server logs or browser history.

**Conclusion**

The username and password are transmitted as Basic Auth header and thus are being encrypted because it is using HTTPS.

---

## [PenTest] Unmasked Display of User Financial Information

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/15](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/15)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

**Impact**

The direct exposure of financial details compromises user privacy and can lead to several adverse consequences. It increases the risk of financial fraud, identity theft, and targeted phishing attacks. Moreover, it undermines user confidence in the application's ability to safeguard their sensitive information, potentially leading to a loss of users and damage to the application's reputation.

**Description**

The application currently displays user financial information, including account balances and transaction details, without any form of masking or concealment. This approach poses a significant privacy and security risk, as sensitive financial data is exposed to prying eyes. In environments where the user's screen may be visible to others, such as public places or workplaces, there is a heightened risk of unauthorized individuals gaining insights into a user's financial status and activities.

![image](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/7cac6fbb-e92f-4d7b-bd5e-36e842ab72f7)

**Recommendations to fix**

Introduce a feature to mask sensitive financial information by default, such as account balances and transaction figures. Users should have the option to reveal this information explicitly, for example, by clicking a "Show" button or hovering over the masked data.

**Conclusion**

After careful evaluation, we acknowledge that the unmasked display of user financial information does expose sensitive data in certain environments; however, given the low risk as assessed and our prioritization of user convenience and current design principles, we have decided not to implement any changes at this time.

---

## [PenTest] Recovery Phrase Vulnerability to Shoulder Surfing Attacks

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/16](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/16)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [nicole-obrien](https://github.com/nicole-obrien)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Impact**

The unmasked display of the recovery phrase compromises the confidentiality and security of user accounts. It directly threatens the integrity and security of the application, undermining user trust and potentially leading to significant reputational damage. Furthermore, it exposes users to a heightened risk of being targeted by attackers, especially in public or semi-public places where shoulder surfing is more feasible.

![image](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/43772fe0-96ad-4cfa-a973-e0f6a69a620e)

**Description**

The recovery phrase, crucial for user account recovery, is currently displayed in plain text within the application. This design makes it vulnerable to shoulder surfing attacks, where an unauthorized individual can directly observe or capture the recovery phrase by looking over the user's shoulder or through other direct observation methods. The exposure of the recovery phrase poses a significant security risk, as it can lead to unauthorized access to user accounts, potentially resulting in financial loss, identity theft, or unauthorized access to sensitive information.

**Recommendations to fix**

Implement a feature that masks the recovery phrase by default, requiring users to explicitly opt to view it. This could be achieved through the use of a "Show/Hide" toggle button.

**Conclusion**

After thorough evaluation, we acknowledge that the current implementation displaying the recovery phrase in plain text exposes users to shoulder surfing risks. However, balancing usability and user expectations with the potential threat, we have decided not to implement any changes at this time, accepting the low risk as it aligns with our current design and user environment considerations.

---

## [PenTest] Disable or limit navigation

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/17](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/17)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [jeeanribeiro](https://github.com/jeeanribeiro)  
**Status:** Resolved

### Description

**Severity**

Medium

**Where**

Pentest , [main.process.ts#L198-L199](https://github.com/bloomwalletio/bloom/blob/develop/packages/desktop/lib/electron/processes/main.process.ts#L198-L199)

**CVSS**

[CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N)

**Impact**

Navigation is a common attack vector. If an attacker can convince your app to navigate away from its current page, they can possibly force your app to open web sites on the Internet. Even if your webContents are configured to be more secure (like having nodeIntegration disabled or contextIsolation enabled), getting your app to open a random web site will make the work of exploiting your app a lot easier.

A common attack pattern is that the attacker convinces the app's users to interact with the app in such a way that it navigates to one of the attacker's pages. This is usually done via links, plugins, or other user-generated content.

**Description**

If the has no need to navigate or only needs to navigate to known pages, it is a good idea to limit navigation outright to that known scope, disallowing any other kinds of navigation.

**Recommendations to fix**

If the app has no need for navigation, we can call event.preventDefault() in a [will-navigate](https://www.electronjs.org/docs/latest/api/web-contents#event-will-navigate) handler. If you know which pages your app might navigate to, check the URL in the event handler and only let navigation occur if it matches the URLs you're expecting.

We recommend that you use Node's parser for URLs. Simple string comparisons can sometimes be fooled - a startsWith('https://example.com') test would let https://example.com.attacker.com through.

```javascript
main.js (Main Process)
const { URL } = require('url')
const { app } = require('electron')

app.on('web-contents-created', (event, contents) => {
  contents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl)

    if (parsedUrl.origin !== 'https://example.com') {
      event.preventDefault()
    }
  })
})

```

**Conclusion**

The app has need for navigation on fiat on-ramp flow because of third-party payment providers. To solve the issue we added a popup for the user to allow or not the opening of external URL.

---

## [PenTest] Application Lacks Automatic Update and Verification

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/19](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/19)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [MarkNerdi](https://github.com/MarkNerdi)  
**Status:** Invalid

### Description

**Severity**

Medium

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:H/A:N)

**Impact**

Users may end up running random unverified and unofficial binaries that would compromise the wallet
and result in the loss of funds.

**Description**

The Bloom App [release](https://github.com/bloomwalletio/bloom/releases/tag/desktop-0.1.7) page contains manual steps to update and verify the binary. The automation of updates through a well-known single source and verification improves and contributes to better end user security.

The Bloom App GitHub release page provides manual steps to download and verify the released binaries for major operating systems. There are several problems with this approach of release, as detailed below.

1. The checksum approach is used by a number of free and open source projects. However, most end users are not developers and may end up skipping this step. Additionally, the release checksums are not signed with a public-key with this approach;
2. The Windows and macOS binaries are not notarized, which would result in a warning when the users invoke the application. This does not provide the user with a sense of security when using the application.

**Recommendations to fix**

We recommend using electronforge or electron-builder. Electron-builder is already being used in the project for building. In addition, the electron-builder project provides ways to [auto-update](https://www.electron.build/auto-update) and do [code-signing](https://www.electron.build/code-signing).

**Conclusion**

This issue is invalid because is not present on the real (production) application.

---

## [PenTest] WebSecurity Sandbox Not Set in Bloom App

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/20](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/20)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [MarkNerdi](https://github.com/MarkNerdi)  
**Status:** Acknowledged

### Description

**Severity**

Low

**Where**

PenTest

**CVSS**

[CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N)

**Impact**

The Electronegativity document, [SANDBOX_JS_CHECK](https://github.com/doyensec/electronegativity/wiki/SANDBOX_JS_CHECK) outlines the following impact:
“Electron extends the default JavaScript APIs (e.g. window.open returns an instance of
BrowserWindowProxy) which leads to a larger attack surface.
Instead, sandboxed renderers expose default JavaScript APIs. Additionally, a sandboxed renderer
does not have a Node.js environment running (with the exception of preload scripts) and the
renderers can only make changes to the system by delegating tasks to the main process via IPC.
Even with nodeIntegration disabled, the current implementation of Electron does not completely
mitigate all risks introduced by loading untrusted resources. As such, it is recommended to enable
sandbox.”

**Description**

Exposing the Electron renderer API to remote code increases the attack surface and leaks information
about the user’s system.

[main.process.ts#L198-L199](https://github.com/bloomwalletio/bloom/blob/develop/packages/desktop/lib/electron/processes/main.process.ts#L198-L199)

```javascript
// Create the browser window
windows.main = new BrowserWindow({
  width: mainWindowState.width,
  height: mainWindowState.height,
  minWidth: 1280,
  minHeight: process.platform === "win32" ? 720 + 28 : 720,
  titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "hidden",
  title: app.name,
  frame: process.platform === "linux",
  icon:
    process.platform === "linux"
      ? path.join(__dirname, `./icons/${process.env.STAGE}/linux/icon.png`)
      : undefined,
  webPreferences: {
    ...DEFAULT_WEB_PREFERENCES,
    preload: paths.preload,
    // Sandboxing is disabled, since our preload script depends on Node.js
    sandbox: false,
  },
});
```

**Recommendations to fix**

We recommend enabling sandbox for remote content and using message passing to facilitate any
necessary calls to sensitive APIs outside of the sandbox environment.

**Conclusion**

In conclusion, we acknowledge the security concern regarding the disabled sandbox. However, the sandbox is set to false because the native modules from iota-sdk require full Node.js integration for proper functionality, making this configuration necessary despite the trade-offs.

---

## [PenTest] Missing Content Security Policy Directives in Bloom Application

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/21](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/21)  
**Author:** [defsec](https://github.com/defsec)  
**Assignee:** [jeeanribeiro](https://github.com/jeeanribeiro)  
**Status:** Resolved

### Description

**Severity**

Medium

**CVSS 3.1**

[CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)

**Where**

PenTest

**Impact**

Bloom App is currently missing a Content Security Policy (CSP). A CSP permits the server that is serving
content to restrict and control the resources Electron is able to load for a given web page. This applies to
any HTML document that is loaded by Electron.

**Description**

Without a CSP in place, requests to arbitrary and untrusted resources will not raise or prevent any errors,
which could be exploited to facilitate data exfiltration. Depending on the precondition, the absence of a
CSP provides an attacker with additional leverage over any foothold they have.

**Recommendations to fix**

We recommend publishing an update with the most restrictive CSP possible, including restrictive
fallbacks that allow the wallet application to function in its current state. Defining a CSP provides a
baseline for security practices and serves as a starting point for a remediation.

Current CSP Settings :

![image](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/assets/79885588/7ee4f3b6-2c16-4428-88aa-8e17141d2951)

**Conclusion**

We added a comprehensive set of content security policy rules on all HTML files.

---

## [PenTest] Postgre_Blind_SQLI at projects

**URL:** [https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/25](https://github.com/AuditOneAuditReviews/bloom_sc_audit_review/issues/25)  
**Author:** [marcocarolasec](https://github.com/marcocarolasec)  
**Assignee:** [RiccardoGalbusera](https://github.com/RiccardoGalbusera)  
**Status:** Resolved

### Description

**Severity**

Critical

**Where**

Found in https://api-prod.tideprotocol.xyz/public/project/1506/leaderboard?cids=*

**Impact**

If exploited, an attacker can gain unauthorized access to sensitive data stored in the PostgreSQL database, compromise user accounts, and potentially execute arbitrary commands on the database server.

---

**Description**

The application is vulnerable to blind SQL injection attacks in the PostgreSQL database. This vulnerability arises due to insufficient input validation and improper sanitization of user-supplied input in SQL queries. Attackers can exploit this vulnerability to manipulate SQL queries and retrieve sensitive information from the database.

A SQL injection vulnerability based on time has been detected on a server that has direct communication with the Bloom Wallet. This implies that if access to this server is gained, certain responses could be poisoned to execute malicious code on the user's side. Below are the obtained evidences, starting with the detection (Respecting the 5 and 10 seconds of sleep).

Moving on to the exfiltration of databases, current username, and banner.

Because it is a very slow exploitation, attempts to gain access to the server have not been made. However, it is recommended to patch this vulnerability as soon as possible.

**Vulnerable Req**

```plaintext
└─# cat req.txt
GET /public/project/1506/leaderboard?cids=* HTTP/2
Host: api-prod.tideprotocol.xyz
Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120"
Accept: application/json
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Bloom/0.1.6 Chrome/120.0.6099.227 Electron/28.2.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: es
```

---

<img width="685" alt="image" src="https://github.com/AuditOneAuditors/marcocarola/assets/58811847/adc29a72-5e42-4950-abf8-a30f6fec120f">

---

<img width="605" alt="image4" src="https://github.com/AuditOneAuditors/marcocarola/assets/58811847/ed43bc31-717a-4c55-8aae-22464d56d8ea">

---

<img width="960" alt="image2" src="https://github.com/AuditOneAuditors/marcocarola/assets/58811847/e199e473-6e4f-41fd-93b1-85374f289597">

---

<img width="956" alt="image3" src="https://github.com/AuditOneAuditors/marcocarola/assets/58811847/7fbb76e8-9b54-4e02-a6ec-6a3cbcdab356">

---

![image5](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/bd2449b3-86de-4b63-ae50-8562a52422a9)

---

![image6](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/ad50857a-9dbc-4e57-a755-df99a434934a)

---

![2024-02-14 10_57_50-Kali-Linux-2022 2-vmware-amd64 - VMware Workstation](https://github.com/AuditOneAuditors/marcocarola/assets/58811847/122fc434-bf3b-433d-8347-e1423f0b152d)

---

**Recommendations to fix:**

1. Implement parameterized queries or prepared statements to prevent SQL injection attacks.
2. Conduct regular security audits and penetration testing to identify and mitigate security vulnerabilities.
3. Educate developers about secure coding practices to avoid introducing vulnerabilities during development.
4. Implement least privilege access controls to restrict database privileges and mitigate the impact of successful attacks.

**Additional context**

This vulnerability was discovered during a security assessment conducted by the AuditOne team. Immediate action is recommended to address this issue and prevent potential security breaches.

**Conclusion**

The issue was on third-party API provider (Tide) and they addressed it, this is the comment of Riccardo Galbusera, one of their team members:

> Hi, I'm Riccardo from Tide team. We addressed this issue in our last release a couple of days ago and now all the involved endpoints have the parameters correctly validated to avoid SQL injections.

---
