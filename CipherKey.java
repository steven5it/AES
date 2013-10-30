public class CipherKey 
{
	// member variables
	private byte[][] initialKey;
	private byte[][] expandedKey;

	public CipherKey()
	{
		initialKey = null;
		expandedKey = null;
	}
	
	public CipherKey(byte[][] arr)
	{
		initialKey = new byte[4][4];
		for (int i = 0; i < arr.length; i++) {
		    System.arraycopy(arr[i], 0, initialKey[i], 0, arr[0].length);
		}
	}
	
	/* accessor methods */
	public byte[][] getInitialKey() {
		return initialKey;
	}
	public byte[][] getExpandedKey() {
		return expandedKey;
	}
	
	public void setExpandedKey (int numRounds)
	{
		assert initialKey != null: "Cannot generate expanded key without initial key";
		expandedKey = new byte[4][(numRounds + 1) * 4];

		//set first portion of expanded key
		for (int i = 0; i < initialKey.length; i++)
			for (int j = 0; j < initialKey[i].length; j++)
				expandedKey[i][j] = initialKey[i][j];		
	}
	
	/* perform rotate operation on key and return resulting array */
	public byte[] keyRotate(int round) 
	{
		//i is the current iteration of 4 iterations, which determines the column of subArray to work on
		byte[] tempArray = new byte[4];
		int col = (4 * round) - 1;						// the column to rotate and return
		tempArray[3] = expandedKey[0][col];
		for (int j = 0; j < 3; j++)
		{
			tempArray[j] = expandedKey[j + 1][col];
		}
		return tempArray;

	}

	/* substitute using s-lookup table */
	public byte[] keySubBytes(byte[] temp, int[] s) 
	{
		int value = 0;
		//i is the current iteration of 4 iterations
		byte[] tempArray = new byte[4];
		for (int j = 0; j < tempArray.length; j++)
		{
			value = temp[j] & 0xFF;
			tempArray[j] = (byte) s[value];
		}
		return tempArray;
	}

	/* perform rcon calculation and substitution */
	public byte[] keyRcon(int round, byte[] temp, int[] rcon) 
	{
		// get the Rcon number using the round as index for Rcon array
		byte[] rcArray = {(byte)rcon[round], 0, 0, 0};
		
		byte[] tempArray = new byte[4];
		for (int j = 0; j < tempArray.length; j++)
		{
			tempArray[j] = (byte) (temp[j] ^ rcArray[j]);
		}
		return tempArray;
		
	}
	
	/* xor the temp array with the column indicated */
	public byte[] xor1(int col, byte[] temp32) 
	{
		byte[] tempArray = new byte[4];
		for (int i = 0; i < tempArray.length; i++)
		{
			tempArray[i] = (byte)(temp32[i] ^ expandedKey[i][col]);
		}
		return tempArray;
	}
	
	/* xor the column with the previous column in the expanded key */
	public byte[] xor(int col, byte[][] temp128) 
	{
		byte[] tempArray = new byte[4];
		for (int i = 0; i < 4; i++)
		{
			tempArray[i] = (byte)(expandedKey[i][col-4] ^ temp128[i][(col % 4) - 1]);
		}
		return tempArray;
	}

	/* print out the expanded key after all rounds */
	public void printExpandedKey() 
	{
		for (int i = 0; i < expandedKey.length; i++)
		{
			for (int j = 0; j < expandedKey[i].length; j++)
			{
				System.out.printf("%02X", expandedKey[i][j]);
				if ((j+1) % 4 == 0)
					System.out.print(" ");
			}
			System.out.println();
		}
		System.out.println();
	}	/* after finishing a round of key scheduling, add 128-bit portion to expanded key */
	public void addToExpandedKey(byte[][] temp128, int round) 
	{
		int subIdx = 4 * round;						// the column of the sub-portion we want to add to
		for (int i = 0; i < temp128.length; i++)
		{
			for (int j = 0; j < temp128[i].length; j++)
			{
				expandedKey[i][subIdx+j] = temp128[i][j];
			}
		}
	}


}
