pipeline {
    agent any

    triggers {
        pollSCM('H/5 * * * *')
    }

    environment {
        REGISTRY      = 'registry.rudy.it.kr'
        IMAGE_NAME    = "${REGISTRY}/auth-spring"
        REGISTRY_CRED = 'registry-rudy-credentials'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    def commit = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.IMAGE_TAG = "${env.BUILD_NUMBER}-${commit}"
                }
            }
        }

        stage('Build Jar') {
            steps {
                sh 'chmod +x gradlew && ./gradlew clean build -x test --no-daemon'
            }
        }

        stage('Build & Push Image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${REGISTRY_CRED}",
                    usernameVariable: 'REGISTRY_USER',
                    passwordVariable: 'REGISTRY_PASS'
                )]) {
                    sh '''
                        docker build -t "$IMAGE_NAME:$IMAGE_TAG" -t "$IMAGE_NAME:latest" .
                        echo "$REGISTRY_PASS" | docker login "$REGISTRY" -u "$REGISTRY_USER" --password-stdin
                        docker push "$IMAGE_NAME:$IMAGE_TAG"
                        docker push "$IMAGE_NAME:latest"
                        docker logout "$REGISTRY"
                    '''
                }
            }
        }
    }
}
