# BTS4410-Obligatorisk-oppgave-3
Dokumentere og programmere en versjon av SUCI funksjonaliteten. Det vil si, dette er inspirert av ECIES/SUCI, men avviker en del fra SUCI slik vi kjenner det fra 5G. Vi skal f.eks. bruk «ConcatKDF» som vår «key derivation function». Videre vil vi bruke AEAD (AES-GCM) for beskyttelsen av identifikatoren.

Av:Daniel Hao Huynh <br>

Dette er min implementasjon av en SUCI funksjonalitet, Deconceal funksjonalitet i tillegg til testing av Deconceal.
### Oppsett av prosjekt
1. sett opp virtuell miljø:
- https://docs.python.org/3/library/venv.html
2. aktiver miljø
- ```sh
  .\.venv\Scripts\activate
  ``` 
3. hent nødvendige moduler:
- ```sh
  pip install -r .\requirements.txt
  ```
### Nødvendige flags
#### Generering av Private og Public key
```sh
python Home.py "keygen"
```
#### Conceal brukerinformasjon
```sh
python User.py "conceal"
```
#### Deconceal brukerinformasjon
```sh
python Home.py "deconceal"
```
### Test resultater
[Testfil](https://github.com/Mystodan/BTS4410-Obligatorisk-oppgave-3/blob/main/test_Home.py)
Alle tester bestått etter Testsett gitt av Geir Køien
> alle funksjonene bestod testdataene tildelt som ZIP av Geir Køien<br>
- [Test set 0](https://github.com/Mystodan/BTS4410-Obligatorisk-oppgave-3/blob/main/TEST_SET_0.zip)
- [Test set 1](https://github.com/Mystodan/BTS4410-Obligatorisk-oppgave-3/blob/main/TEST_SET_1.zip)
- [Test set 2](https://github.com/Mystodan/BTS4410-Obligatorisk-oppgave-3/blob/main/TEST_SET_2.zip)
 


for å reprodusere resultatene, tast inn fra rot: <br>
```sh
python -m unittest
```

