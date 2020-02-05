# Generate the RSA keys

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout > public.pem

# print the keys in an escaped format

awk -v ORS='\\n' '1' private.pem
awk -v ORS='\\n' '1' public.pem
