To run one of our end-to-end PIR schemes over a simulated DB of a given size, run this command:
`go test -v ./pir/... -run e2e`

Pass the following environment variables to this command: 
1. LOG2_NUMBER_OF_ROWS - this should be an integer for the number of rows of the database which to conduct the PIR protocol.
2. LOG2_NUM_DB_ROWS - this should be an integer for the number of rows in the ''actual" database. It should be less than or equal to the one above.
3. MODE - this is a string corresponding to the PIR scheme to run. It should be one of: "RLWE_All_Keys", "RLWE_Whispir_2_Keys", "RLWE_Whispir_3_Keys" or "Basic_Paillier".
4. ROW_SIZE - size of each row in the database. 

You can set them as follows: 

`LOG2_NUMBER_OF_ROWS=8 LOG2_NUM_DB_ROWS=4 ROW_SIZE=1600 MODE=BasicPaillier go test -v ./pir/... -run e2e`