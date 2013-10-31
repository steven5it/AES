import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class AES 
{
	// s-box
	public static final int[] s = 
		{
		   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
		   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
		   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
		   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
		   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
		   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
		   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
		   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
		   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
		   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
		   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
		   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
		   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
		   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
		   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		};
	// rcon
	public static final int[] Rcon = {
		0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
		0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
		0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
		0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
		0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
		0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
		0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
		0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
		0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
		0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
		0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
		0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
		0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
		0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
		0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
		0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};
	
	
	public static void main (String[] args) throws IOException
	{
		long start = System.currentTimeMillis(); // begin timer
		/* validate arguments */
		validateArgs(args);
		
		/* variable declaration */
		char option = args[0].charAt(0);						// command line option to encrypt or decrypt 
		String keyFileName = args[1];							// name of keyFile
		String inputFileName = args[2];							// name of inputFile
		
		byte[][] inputArray = new byte[4][4];
		byte[][] keyArray = new byte[4][4];
		
		/* read in inputFile and keyFile and store into respective arrays */
		BufferedReader keyReader = new BufferedReader (new FileReader(keyFileName));
				
		/* convert String of hex characters for key into 4 x 4 array of bytes, key array only needs to be stored once */
		String keyLine = keyReader.readLine();
		validateKey(keyLine);
		int j = 0;
		for (int i = 0; i < keyLine.length(); i+=2)
		{
		    int value1 = hex2decimal(keyLine.charAt(i));
		    int value2 = hex2decimal(keyLine.charAt(i+1));
		    if (value1 == -1 || value2 == -1)								// invalid hex character, continue to next line
		    {
		    	System.err.println("keyFile has invalid hex characters");
		    	System.exit(-1);
		    }
		    byte byteValue = (byte)((value1 << 4) | value2);
		    
		    // hex character is valid, so add to inputArray
			keyArray[j%4][j/4] = byteValue;
			j++;
		}
		/* Expand the cipherKey */
		int numRounds = 10;						// number of key expansion rounds
		int round = 1;							// indicates the current round
		CipherKey key = new CipherKey(keyArray);
		key.setExpandedKey(numRounds);			// set size of the expanded key, and add initial key to it
		while (round <= numRounds)				// perform numRounds rounds
		{
			byte[][] temp128 = new byte[4][4];		// temporary array to represent each complete round
			for (int i = 0; i < 4; i++)				// a 128-bit cipherkey requires operations on 4 32-bit sections
			{
				byte[] temp32 = new byte[4];		// temporary array to perform 32-bit operations on
				// the first column of each round requires more steps
				if (i == 0)
				{
					temp32 = key.keyRotate(round);
					temp32 = key.keySubBytes(temp32, s);
					temp32 = key.keyRcon(round, temp32, Rcon);
					temp32 = key.xor1((round - 1) * 4, temp32);
				}
				// columns 2-4 only require xor previous column with 4 columns previous
				else
				{
					temp32 = key.xor((round * 4) + i, temp128);
				}
				
				// at this point we have complete transformed 32-bit key portion, copy into full key for the round
				for (int k = 0; k < 4; k++)
				{
					temp128[k][i] = temp32[k];		
				}
			}
			key.addToExpandedKey(temp128, round);
			round++;
		}
		keyReader.close();

		/* inputText may contain multiple lines to be encrypted/decrypted */
		String line = null;
		BufferedReader inputReader = new BufferedReader (new FileReader(inputFileName));
		String extension = (option == 'e') ? "enc" : "dec"; 							// set the extension needed for output file
		BufferedWriter bw = new BufferedWriter(new FileWriter(inputFileName + "." + extension));

		// continue reading in lines to encrypt/decrypt if they exist
		int count = 0; 				// count of number of lines encrypted/decrypted
		boolean first = true;
		while ((line = inputReader.readLine()) != null)
		{
			boolean validHex = true;								// indicates whether the line has valid hex characters
			/* check for a valid line of 32 hex characters, pad if shorter than 32 */
			if (line.length() > 32)
				continue;
			if (line.length() < 32)
				line = padZeros(line);

			// we have a valid line to encrypt/decrypt at this point
			/* convert String of hex characters into 4 x 4 array of bytes */
		    j = 0;
			
			for (int i = 0; i < line.length(); i+=2)
			{
			    int value1 = hex2decimal(line.charAt(i));
			    int value2 = hex2decimal(line.charAt(i+1));
			    if (value1 == -1 || value2 == -1)								// invalid hex character, continue to next line
			    {
			    	validHex = false;
			    	break;
			    }
			    byte byteValue = (byte)((value1 << 4) | value2);
//			    System.out.printf("value 1 = %02X, value 2 = %02X, byteValue: %02X \n", value1, value2, byteValue);
			    
			    // hex character is valid, so add to inputArray
				inputArray[j%4][j/4] = byteValue;
				j++;
			}
			if (!validHex)										// if string contains invalid hex characters, continue to next line
				continue;
			
			/* output initial plaintext/ciphertext arrays and key array */
			String err = "";							
			err = ((option == 'e') ? "Plaintext": "Ciphertext");
			System.out.println("The " + err + " is:");
			printByteArray(inputArray);
			System.out.println("The CipherKey is:");
			printByteArray(keyArray);
			
			/* output the expanded key */
			System.out.println("The expanded key is:");
			key.printExpandedKey();
			// expanded key has completed, begin rounds on inputText
			
			// check if e or d option set for encryption or decryption
			if (option == 'e')
			{
				// perform encryption
				Encryption e = new Encryption(inputArray);
				
				int encRound = 0;
				while (encRound <= numRounds)
				{
					if (encRound == 0)							// addRoundKey once before 1st round begins
					{
						System.out.println("After addRoundKey(" + encRound + "):");
						e.addRoundKey(encRound, key.getExpandedKey());
						e.printCipherTemp();
						encRound++;
						continue;
					}
					/* subBytes, shiftRows, mixColumns, addRoundKey */
					System.out.println("After subBytes:");
					e.subBytes(s);
					e.printCipherTemp();
					System.out.println("After shiftRows:");
					e.shiftRows();
					e.printCipherTemp();
					if (encRound != 10)							// skip mixColumns in round 10
					{
						System.out.println("After mixColumns:");
						for (int i = 0; i < 4; i++)
						{
							e.mixColumns(i);
						}
						e.printCipherTemp();
					}

					System.out.println("After addRoundKey(" + encRound + "):");
					e.addRoundKey(encRound,  key.getExpandedKey());
					e.printCipherTemp();
					
					encRound++;
				}
				System.out.println("The ciphertext:");
				printByteArray(e.getCipherTemp());
				
				// output completed encryption into encryption file
				if (!first) bw.newLine();
				first = false;
				writeTextFile(bw, e.getCipherTemp());
				
				
			}
			
			// decryption
			else
			{
				// perform decryption
				Decryption d = new Decryption(inputArray);
				
				// round starts at 10 and counts down
				numRounds = 0;
				int decRound = 10;
				while (decRound >= numRounds)
				{
					if (decRound == 10)							// addRoundKey once before 1st round begins
					{
						System.out.println("After addRoundKey(" + decRound + "):");
						d.addRoundKey(decRound, key.getExpandedKey());
						d.printPlainTemp();
						decRound--;
						continue;
					}
					
					// skip invMixColumns in round 10 (starting from 10 to 1)
					if (decRound != 9)
					{
						System.out.println("After invMixColumns:");
						for (int i = 0; i < 4; i++)
						{
							d.invMixColumns(i);
						}
						d.printPlainTemp();
					}
					
					/* invMix (above), invShiftRows, invSubBytes, addRound */
					System.out.println("After invShiftRows:");
					d.invShiftRows();
					d.printPlainTemp();
					System.out.println("After invSubBytes:");
					d.invSubBytes(s);
					d.printPlainTemp();
					System.out.println("After addRoundKey(" + decRound + "):");
					d.addRoundKey(decRound,  key.getExpandedKey());
					d.printPlainTemp();
					decRound--;
				}
				
				System.out.println("\nThe decryption of the ciphertext:");
				printByteArray(d.getPlainTemp());
				
				// output completed encryption into encryption file
				if (!first) bw.newLine();
				first = false;
				writeTextFile(bw, d.getPlainTemp());
			}
			count++;
		}
		bw.close();
		inputReader.close();
		long end = System.currentTimeMillis();
		System.out.println("ms: " + (end-start));
		double seconds = (end - start)/1000000.0;
		System.out.printf("s: %f\n", seconds);
		double mb = (double)((count*16.0)/1048576.0);
		System.out.printf("MB: %f\n", mb);
		System.out.printf("MB/sec = %f\n", mb/seconds);
		
	}

	/* write array to file */
	private static void writeTextFile(BufferedWriter bw,
			byte[][] arr) throws IOException 
	{
		for (int i = 0; i < arr.length; i++)
		{
			for (int j = 0; j < arr[i].length; j++)
			{
				String s = String.format("%02X", arr[j][i]);
				bw.write(s, 0, 2);
			}
		}
	}

	/* print starting array after validation has been completed */
	private static void printByteArray(byte[][] arr) {
		for (int i = 0; i < arr.length; i++)
		{
			for (int j = 0; j < arr[i].length; j++)
			{
				System.out.printf("%02X ", arr[i][j]);
			}
			System.out.println();
		}	
		System.out.println();
	}

	/* validate the keyInput file */
	private static void validateKey(String keyLine) {
		if (keyLine == null)
		{
			System.err.println("keyFile is empty");
			System.exit(-1);
		}
		if (keyLine.length() != 32)
		{
			System.err.println("keyFile length needs to be 32");
			System.exit(-1);	
		}
		
	}

	/* pad the line with zeroes until the string length is 0 */
	private static String padZeros(String line) {
		while (line.length() < 32)
			line += '0';
		return line;
	}

	/* Performs validation of command line arguments */
	private static void validateArgs(String[] args) {
		
		if (args.length != 3)
		{
			System.err.println("Incorrect number of arguments, usage: java AES option keyFile inputFile");
			System.exit(-1);
		}
			
		if (args[0].length() != 1 || (args[0].charAt(0) != 'e' && args[0].charAt(0) != 'd'))
		{
			System.err.println("first argument (option) must be e or d");
			System.exit(-1);
		}
			
	}

	public static int hex2decimal (char hexChar)
	{
		char c = Character.toUpperCase(hexChar);
		if (c >= '0' && c <= '9')
			return c - '0';
		else if (c >= 'A' && c <= 'F')
			return (10 + c -'A');
		else
		{
			return -1;
		}	
	}
}
