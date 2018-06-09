

def main():
    client = HSClient(api_key='cd024ab0dbbd0f138420f793da365b0e879180a083924c8b2ac7b9dbee48e35c')
    # x = client.send_signature_request(
    #     test_mode=True,
    #     title="title=NDA with Acme Co.",
    #     subject="The NDA we talked about",
    #     message="Please sign this NDA and then we can discuss more. Let me know if you have any questions.",
    #     signers=[{'email_address': 'shikharbakhda@gmail.com', 'name': 'Shikhar Bakhda'}],
    #     files=['/Users/sbakhda/dev/cryptech/cryptech/test.pdf']
    # )
    # print(x)
    # print(client.get_signature_request(x.signature_request_id))
    # client.get_signature_request_file(
    #     signature_request_id= '59c20e2076954d9ecdadaf779417afec067a85a0',
    #     filename='SignedContract.pdf'
    # )
