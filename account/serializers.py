import re
from rest_framework import serializers
from django.contrib.auth.models import User

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')

# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=8,write_only=True)
    error_message = {
        'username': 'Username fields only contain alphanumeric characters',}
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')   

        if not username.isalnum():
            raise serializers.ValidationError(
                self.error_message)

        if not re.findall('\d', password):
                raise serializers.ValidationError(
                    ("The password must have digit 0-9."),
                    code='no_number_password',
                )       

        if not re.findall('[A-Z]', password):
            raise serializers.ValidationError(
                ("The password must have 1 uppercase letter, A-Z."),
                code='no_upper_password',
            )

        if not re.findall('[a-z]', password):
            raise serializers.ValidationError(
                ("The password must have lowercase letter, a-z."),
                code='no_lower_password',
            ) 

        if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', password):
            raise serializers.ValidationError(
                ("The password must have 1 symbol: " +
                  "()[]{}|\`~!@#$%^&*_-+=;:'\",<>./?"),
                code='no_symbol_password',
            )   
        return attrs     

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
        return user