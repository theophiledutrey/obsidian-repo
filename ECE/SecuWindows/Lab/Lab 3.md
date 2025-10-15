![[Pasted image 20251015172854.png]]

![[Pasted image 20251015172913.png]]

![[Pasted image 20251015173933.png]]

![[Pasted image 20251015174640.png]]

![[Pasted image 20251015174718.png]]

![[Pasted image 20251015174805.png]]

![[Pasted image 20251015175030.png]]

![[Pasted image 20251015175735.png]]

### Commands used and their purpose

1. **Add a recovery password protector**
    
    `manage-bde -protectors -add C: -RecoveryPassword`
    
    ➤ **Purpose:**  
    Adds a _numerical recovery password_ protector to the BitLocker volume.  
    This password is a 48-digit recovery key that can be used to unlock the drive if the TPM or automatic unlock fails.  
    It ensures there is always a manual method to recover access to the encrypted disk.
    

---

2. **Add a TPM protector**
    
    `manage-bde -protectors -add C: -TPM`
    
    ➤ **Purpose:**  
    Configures BitLocker to use the Trusted Platform Module (TPM) chip for secure key storage and automatic unlocking during system boot.  
    The TPM ensures that the encryption keys are released only if the system’s integrity (boot files, firmware, etc.) is verified.
    

---

3. **Start encryption (used space only)**
    
    `manage-bde -on C: -UsedSpaceOnly`
    
    ➤ **Purpose:**  
    Starts the BitLocker encryption process on the `C:` drive, but encrypts only the sectors that currently contain data.  
    This makes the encryption process faster while still securing all existing data.
    

---

4. _(Optional verification)_
    
    `manage-bde -status`
    
    ➤ **Purpose:**  
    Displays the current BitLocker configuration and encryption progress for each drive, confirming that the TPM and recovery protectors are active and that encryption is ongoing.

![[Pasted image 20251015175916.png]]

### **1. Explain why you are not able to access the VM’s drive anymore**

After enabling BitLocker encryption on the WIN-CLI2 virtual machine, the virtual hard disk (`.vhdx`) is now fully encrypted.  
This means that all data stored on the disk is protected by encryption keys that are securely managed by the TPM (Trusted Platform Module) or by a recovery key.

When the VM is shut down and the `.vhdx` file is mounted offline (for example, from the host system or another VM), the content appears **inaccessible or unreadable** because:

- The **encryption key is not available** outside the original Windows installation.
    
- The **TPM protector** only releases the decryption key when the system’s integrity is verified during the normal boot process.
    

**In short:** the data is encrypted at rest, and without the correct protectors (TPM or recovery key), the disk cannot be accessed.

---

### **2. Imagine you are an attacker trying to corrupt the WIN-CLI2 virtual machine. What are the two options to access the drive’s content offline?**

| **Option**                            | **Description**                                                                                                                                                                                                  | **What would be needed**                                                                                                                    | **Difficulty**                                                                                                                 |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **1. Use the BitLocker Recovery Key** | The attacker could try to obtain the 48-digit BitLocker recovery key generated during encryption. Using this key, they could unlock the drive from another Windows system using `manage-bde -unlock` or the GUI. | Access to the recovery key (usually stored by the admin, printed, or exported during setup).                                                | **Very difficult**, since the key is not stored in plaintext and is meant to be kept secret.                                   |
| **2. Extract the TPM-protected key**  | The attacker could attempt to copy or dump the VM’s TPM module and extract the encryption key from it.                                                                                                           | Advanced forensic tools, knowledge of TPM internals, and possibly administrative access to the hypervisor to extract the virtual TPM state. |  **Extremely difficult**, because TPM is designed to prevent key extraction — it only releases keys to trusted boot sequences. |

---

### **Summary**

BitLocker effectively protects the VM’s disk by binding the encryption keys to the TPM and/or recovery password.  
Without one of those, accessing or tampering with the `.vhdx` file offline is **nearly impossible** — this is precisely the security goal of BitLocker.

![[Pasted image 20251015180235.png]]

![[Pasted image 20251015181052.png]]

![[Pasted image 20251015181532.png]]

![[Pasted image 20251015181634.png]]

![[Pasted image 20251015181655.png]]

When comparing the two XML logs, the only PCR value that differs between the two measured boot results is **PCR 7**.  
All other PCRs (such as PCR 0) remain identical, but the **EventDigest** associated with **PCR 7** changes between the logs.

**Justification:**  
PCR 7 is used by the TPM to record measurements related to **Secure Boot configuration, UEFI drivers, and boot policy**.  
When Secure Boot is enabled or disabled, the firmware configuration changes, which causes the TPM to extend a different hash value into PCR 7.  
This means that the system integrity and boot environment have changed — exactly what the TPM is designed to detect.

**In summary:**  
PCR 7 changed because the Secure Boot state was modified between the two boots, altering the boot measurements stored in the TPM.

**Which PCR changed?**  
**PCR 7.**

**What does PCR 7 measure (high level)?**  
PCR 7 reflects the **UEFI Secure Boot state & policy**: whether Secure Boot is enabled/disabled and the authenticated variables/policies/keys that define it (PK/KEK/db/dbx). In short: _Secure Boot configuration integrity_.

**How is this PCR used by BitLocker?**  
BitLocker seals its Volume Master Key (VMK) to TPM PCR values that describe a “trusted boot” on UEFI systems—**including PCR 7**. If the Secure Boot state/policy changes, PCR 7’s hash changes, so the TPM **won’t unseal** the VMK and BitLocker cannot auto-unlock.

**Why did Windows ask for the recovery key?**  
Between boots, the Secure Boot configuration changed (e.g., Secure Boot disabled or policy altered). That changed **PCR 7**, causing a **PCR mismatch** against what BitLocker expected. Because the TPM refused to release the VMK, Windows entered **BitLocker recovery** and therefore prompted for the **48-digit recovery key**.


![[Pasted image 20251015182657.png]]

![[Pasted image 20251015183106.png]]

**1. How can you ensure that HVCI is effectively running?**  
You can confirm that **Hypervisor-Enforced Code Integrity (HVCI)** is effectively running by checking the **“Virtualization-based security Services Running”** section in _msinfo32.exe_.  
If **“Hypervisor Enforced Code Integrity”** appears in this list, it means that HVCI is active and protecting the system memory and kernel code integrity through virtualization-based security.

---

**2. What is the meaning of the “Virtualization-based security Available Security Properties” value?**  
This field lists the VBS features that the system’s hardware and firmware support, such as:

- **Base Virtualization Support** – the CPU and hypervisor can create secure memory regions.
- **Secure Boot** – verifies the integrity of boot components.
- **DMA Protection / UEFI Code Readonly** – prevents unauthorized memory access and modification of firmware code.

In short, this value indicates **which VBS capabilities are supported and can be enabled** on the current hardware platform.

---

**3. What does it mean if a VBS service is present in “Configured” but absent from “Running”?**  
It means that the service has been **enabled in Group Policy**, but **is not currently active**.  
This can happen if:

- A **reboot** is still required for the change to take effect,
- The **hardware or firmware** does not support that specific feature, or
- There was a **configuration conflict or dependency issue** preventing it from starting.

In short, **“Configured but not Running” = planned/expected, but not yet enforced in the active system state.**


![[Pasted image 20251015184149.png]]

![[Pasted image 20251015184321.png]]

![[Pasted image 20251015184934.png]]

![[Pasted image 20251015184919.png]]


The fundamental weakness of controlling a security service through an **OS-level parameter** is that it relies on **software running within the same environment it is supposed to protect**.  
This means that if an attacker gains administrative or kernel-level privileges, they can **modify or disable** those configuration settings directly from the operating system — for example, through Group Policy, the registry, or boot parameters.

Because the configuration is stored and enforced **after the operating system has already started**, it is **not protected by hardware isolation**.  
Disabling VBS simply requires:

- Access to the OS or registry (administrative rights),
- Modifying a policy or boot setting, and
- Rebooting the system.

![[Pasted image 20251015185632.png]]

![[Pasted image 20251015190259.png]]

### **1. What setting was changed to prevent disabling the VBS services from the operating system**

In the **Local Group Policy Editor**, the setting **“Turn On Virtualization Based Security”** was configured as:

- **Enabled**
- **Virtualization Based Protection of Code Integrity:** → **Enabled with UEFI lock**

This configuration activates **Hypervisor-Enforced Code Integrity (HVCI)** and applies a **UEFI lock**, which stores the configuration in firmware rather than only in the operating system.  
As a result, the protection cannot be turned off from within Windows, even by an administrator, because the policy is enforced at the firmware level.

---

### **2. Why the VBS setting cannot be modified from the operating system (UEFI explanation)**

When Windows applies the **“Enabled with UEFI lock”** option, it writes the configuration to a UEFI variable using the **`SetVariable()`** API defined in the UEFI specification.  
The variable is created with the following attributes:

- **`EFI_VARIABLE_NON_VOLATILE`** → The variable is stored in non-volatile UEFI memory (NVRAM) and persists across reboots.
- **`EFI_VARIABLE_BOOTSERVICE_ACCESS`** → The variable can only be accessed by firmware and UEFI boot services, not by a running operating system.

Because of these attributes, once Windows writes the configuration into UEFI memory, it can no longer modify or delete it after the system has booted into the OS.  
Only firmware-level code (for example, a BIOS/UEFI setup utility or firmware update) can change or clear this variable.