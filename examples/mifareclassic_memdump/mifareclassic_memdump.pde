/**************************************************************************/
/*! 
    @file     mifareclassic_memdump.pde
    @author   Adafruit Industries
	@license  BSD (see license.txt)

    This example attempts to dump the contents of a Mifare Classic 1K card
	
    Note that you need the baud rate to be 115200 because we need to print
	out the data and read from the card at the same time!

    This is an example sketch for the Adafruit PN532 NFC/RFID breakout boards
    This library works with the Adafruit NFC breakout 
      ----> https://www.adafruit.com/products/364
 
    Check out the links above for our tutorials and wiring diagrams 
    These chips use I2C to communicate

    Adafruit invests time and resources providing this open source code, 
    please support Adafruit and open-source hardware by purchasing 
    products from Adafruit!

*/
/**************************************************************************/

#include <Wire.h>
#include <Adafruit_NFCShield_I2C.h>

#define IRQ   (2)
#define RESET (3)  // Not connected by default on the NFC Shield

// ***********************
// TODO: !!! IMPORTANT !!!
// ***********************
// Set this field depending on if this is an NDEF formatted card.  
// For a non-NDEF card (for example an unformatted Mifare Classic card), 
// set this to 0.  
//
// NDEF formatted cards use specific keys for authentication, and the
// authentication requests will fail if you use the default Mifare keys
// (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for both key a and key B).
//
// Note that you will no longer be able to authenticate non-NDEF blocks
// when using NDEF keys since they will not match what is being provided.
// Also, because key a changes in block 0 (the MAD Sector for NDEF
// records), NDEF formatted cards will no longer work in normal
// Mifare mode.  Cards should be treated as NDEF or not, and it's best
// not to mix them because key managed becomes complicated.
//
// Possible values:
//
// READ_AS_NDEF = 0    No NDEF Sectors ... use default Mifare Classic keys
// READ_AS_NDEF = 1    NDEF Formatted Card ... use NDEF keys (only NDEF blocks will authenticate!)
//
// For more information see: 
//
// http://www.ladyada.net/products/rfidnfc/mifare.html
// http://www.ladyada.net/products/rfidnfc/ndef.html

#define READ_AS_NDEF (0)

Adafruit_NFCShield_I2C nfc(IRQ, RESET);

void setup(void) {
  // has to be fast to dump the entire memory contents!
  Serial.begin(115200);
  Serial.println("Looking for PN532...");

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX); 
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC); 
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);
  
  // configure board to read RFID tags
  nfc.SAMConfig();
  
  Serial.println("Waiting for an ISO14443A Card ...");
}


void loop(void) {
  uint8_t success;                          // Flag to check if there was an error with the PN532
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t currentblock;                     // Counter to keep track of which block we're on
  bool authenticated = false;               // Flag to indicate if the sector is authenticated
  uint8_t data[16];                         // Array to store block data during reads

  // Use the appropriate keys depending on whether this is an NDEF card or not
  #if READ_AS_NDEF == 1
    // Use the NDEF keys and read NDEF blocks
    uint8_t keya[6] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    uint8_t keyb[6] = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };
  #else
    // Use the default (non-NDEF) Mifare card keys
    uint8_t keya[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t keyb[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  #endif 
    
  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  
  if (success) {
    // Display some basic information about the card
    Serial.println("Found an ISO14443A card");
    Serial.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    Serial.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    Serial.println("");
    
    if (uidLength == 4)
    {
      // We probably have a Mifare Classic card ... 
      Serial.println("Seems to be a Mifare Classic card (4 byte UID)");
      
      // Now we try to go through all 16 sectors (each having 4 blocks)
      // authenticating each sector, and then dumping the blocks            
      for (currentblock = 0; currentblock < 64; currentblock++)
      {
        // Check if this is a new block so that we can reauthenticate
        if (nfc.mifareclassic_IsFirstBlock(currentblock)) authenticated = false;
        
        // If the sector hasn't been authenticated, do so first
        if (!authenticated)
        {
          // Starting of a new sector ... try to to authenticate
          Serial.print("------------------------Sector ");Serial.print(currentblock/4, DEC);Serial.println("-------------------------");
		  if (currentblock == 0)
		  {
			// This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
			// or 0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 for NDEF formatted cards
			success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 0, keya);
		  }
		  else
		  {
			// This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
			// or 0xD3 0xF7 0xD3 0xF7 0xD3 0xF7 for NDEF formatted cards
			success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 0, keyb);
		  }
          if (success)
          {
            authenticated = true;
          }
          else
          {
            Serial.println("Authentication error");
          }
        }        
        // If we're still not authenticated just skip the block
        if (!authenticated)
        {
          Serial.print("Block ");Serial.print(currentblock, DEC);Serial.println(" unable to authenticate");
        }
        else
        {
          // Authenticated ... we should be able to read the block now
          // Dump the data into the 'data' array
          success = nfc.mifareclassic_ReadDataBlock(currentblock, data);
          if (success)
          {
            // Read successful
            Serial.print("Block ");Serial.print(currentblock, DEC);
            if (currentblock < 10)
            {
              Serial.print("  ");
            }
            else
            {
              Serial.print(" ");
            }
            // Dump the raw data
            nfc.PrintHexChar(data, 16);
          }
          else
          {
            // Oops ... something happened
            Serial.print("Block ");Serial.print(currentblock, DEC);
            Serial.println(" unable to read this block");
          }
        }       
      }
    }
    else
    {
      Serial.println("Ooops ... this doesn't seem to be a Mifare Classic card!"); 
    }
  }
  // Wait a bit before trying again
  Serial.println("\n\nSend a character to run the mem dumper again!");
  Serial.flush();
  while (!Serial.available());
  while (Serial.available()) {
	Serial.read();
  }
  Serial.flush();
}
