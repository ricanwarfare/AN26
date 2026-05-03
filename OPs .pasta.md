


# Ops Plan

## Scheme of Maneuver

```text
>Operations Box (172.16.0.10)
->Target 1 (192.168.0.213)
-->Target 2 (192.168.0.7)
--->Target 3 (IP Unknown)
```

---

## Instructions

- [ ] Access targets only when directed
- [ ] Follow the Scheme of Maneuver in order
- [ ] Complete all required questions/tasks before proceeding
- [ ] Build and maintain a cut sheet during execution

---

# Targets

---

## Target 1

### Access
- **Method:** SSH
- **Host:** `192.168.0.213`

### Credentials
- **Username:** John
- **Password:** forthepeople

### Tasks
- [ ] Access via SSH
- [ ] task
- [ ] task

### Notes
> Add notes here

---

## Target 2

### Access
- **Method:** RDP (via Target 1)
- **Host:** `192.168.0.7`

### Credentials
- **Username:** Emmett
- **Password:** onepointtwentyonejigowatts

### Tasks
- [ ] Pivot from Target 1
- [ ] RDP from win7local
- [ ] Complete PCTE questions
- [ ] Update Windows cut sheet
- [ ] Access `Tools` share on win10local
- [ ] Run `nc.exe`
- [ ] Connect to Target 3 listener on port `8080`
- [ ] Collect Target 3 credentials

### Notes
> Add notes here

---

## Target 3

### Access
- **Method:** SSH via implant credentials
- **Host:** Unknown

### Tasks
- [ ] Connect to implant


### Notes
> Add notes here

---



