pipeline {
    agent any

    // GitHub Poll SCM — 5분 간격으로 변경 사항 확인
    triggers {
        pollSCM('H/5 * * * *')
    }

    environment {
        REGISTRY      = 'registry.rudy.it.kr'
        IMAGE_NAME    = "${REGISTRY}/auth-spring"
        // Jenkins Credentials(Username with password)에 등록한 registry 계정의 ID
        REGISTRY_CRED = 'registry-rudy-credentials'
        // 애플리케이션용 docker-compose.yml — 배포 대상 서버의 고정 경로 (DB/Redis용 compose와 별도)
        COMPOSE_FILE  = '/workspace/auth-spring/application'
        // 배포 대상 서버 — 지금은 Jenkins와 같은 서버지만, 원격 서버로 바뀌어도 이 값만 교체하면 됨
        DEPLOY_HOST     = '192.168.0.2'
        // Jenkins Credentials(SSH Username with private key)에 등록한 배포 계정의 ID
        DEPLOY_SSH_CRED = 'deploy-server-ssh'
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

        // Dockerfile은 build/libs/*.jar를 그대로 복사하는 구조이므로
        // 이미지 빌드 전에 jar를 먼저 만든다 (Jenkins 컨테이너에 설치된 JDK21로 직접 빌드)
        stage('Build Jar') {
            steps {
                sh '''
                    export JAVA_HOME=$(update-alternatives --list java | grep "java-21" | sed "s|/bin/java||")
                    chmod +x gradlew && ./gradlew build -x test --no-daemon
                '''
            }
        }

        // docker 데몬 없이 Kaniko executor로 이미지 빌드 + 레지스트리 push까지 한 번에 처리
        // (docker.sock 마운트 불필요 — Jenkins 컨테이너 안에서 일반 프로세스로 실행)
        stage('Build & Push Image') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${REGISTRY_CRED}",
                    usernameVariable: 'REGISTRY_USER',
                    passwordVariable: 'REGISTRY_PASS'
                )]) {
                    sh '''
                        export DOCKER_CONFIG="$PWD/.docker"
                        mkdir -p "$DOCKER_CONFIG"
                        AUTH=$(printf "%s:%s" "$REGISTRY_USER" "$REGISTRY_PASS" | base64 -w0)
                        printf '{"auths":{"%s":{"auth":"%s"}}}' "$REGISTRY" "$AUTH" > "$DOCKER_CONFIG/config.json"

                        mkdir -p "$PWD/.kaniko"
                        executor \
                            --kaniko-dir="$PWD/.kaniko" \
                            --context="dir://$PWD" \
                            --dockerfile=Dockerfile \
                            --destination="$IMAGE_NAME:$IMAGE_TAG" \
                            --destination="$IMAGE_NAME:latest" \
                            --cleanup
                    '''
                }
            }
        }

        stage('Deploy') {
            steps {
                // 배포 대상 서버에 SSH로 접속해 명령만 실행 — docker.sock 마운트에 의존하지 않으므로
                // 대상이 원격 서버로 바뀌어도 DEPLOY_HOST/DEPLOY_SSH_CRED만 바꾸면 됨
                withCredentials([sshUserPrivateKey(
                    credentialsId: "${DEPLOY_SSH_CRED}",
                    keyFileVariable: 'SSH_KEY',
                    usernameVariable: 'SSH_USER'
                )]) {
                    sh '''
                        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$DEPLOY_HOST" \
                            "docker compose -f $COMPOSE_FILE pull && docker compose -f $COMPOSE_FILE up -d && docker image prune -f"
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "배포 완료: ${IMAGE_NAME}:${IMAGE_TAG}"
        }
        failure {
            echo '빌드 또는 배포 실패'
        }
    }
}
