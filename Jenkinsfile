pipeline {
    agent any

    triggers {
        pollSCM('H/5 * * * *')
    }

    environment {
        REGISTRY      = 'registry.rudy.it.kr'
        IMAGE_NAME    = "${REGISTRY}/auth-spring"
        REGISTRY_CRED = 'registry-rudy-credentials'
        // 배포 대상 서버 — 지금은 Jenkins와 같은 호스트라 host.docker.internal 사용,
        // 원격 서버로 바뀌면 그 서버의 실제 주소로 교체하면 됨
        DEPLOY_HOST     = 'host.docker.internal'
        // Jenkins Credentials(SSH Username with private key)에 등록한 배포 계정의 ID
        DEPLOY_SSH_CRED = 'deploy-server-ssh'
        // 배포 대상 서버의 docker-compose.yml이 위치한 디렉터리
        COMPOSE_DIR     = '/workspace/auth-spring/application'
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

        stage('Deploy') {
            steps {
                // 배포 대상 서버에 SSH로 접속해 명령만 실행 — 대상이 원격 서버로 바뀌어도
                // DEPLOY_HOST/DEPLOY_SSH_CRED만 바꾸면 됨
                withCredentials([sshUserPrivateKey(
                    credentialsId: "${DEPLOY_SSH_CRED}",
                    keyFileVariable: 'SSH_KEY',
                    usernameVariable: 'SSH_USER'
                )]) {
                    sh '''
                        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$DEPLOY_HOST" \
                            "cd $COMPOSE_DIR && docker compose pull && docker compose up -d && docker image prune -f"
                    '''
                }
            }
        }
    }
}
