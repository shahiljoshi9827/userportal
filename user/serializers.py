from rest_framework import serializers
from user.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    otp = serializers.CharField(required=False)
    password = serializers.CharField(required=False)

    # class Meta:

    def validate(self, attrs):
        email = attrs.get('email')
        otp = attrs.get('otp')
        password = attrs.get('password')

        if not email:
            raise serializers.ValidationError('Email is required.')

        if not password:
            raise serializers.ValidationError('Password is required when using email login.')

        if otp and len(otp) != 6:
            raise serializers.ValidationError('OTP must be 6 digits.')

        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')

    class Meta:
        model = User
        fields = ('first_name', 'last_name')

    def update(self, instance, validated_data):
        user = instance.user
        user.first_name = validated_data['first_name']
        user.last_name = validated_data['last_name']
        user.save()
        return instance
