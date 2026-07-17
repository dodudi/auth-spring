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
        // 애플리케이션용 docker-compose.yml — 서버 고정 경로 (DB/Redis용 compose와 별도)
        COMPOSE_FILE  = '/opt/app/docker-compose.yml'
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
        // 이미지 빌드 전에 jar를 먼저 만든다 (Jenkins 컨테이너 자체엔 JDK를 두지 않고
        // 빌드 전용 컨테이너를 띄워 처리 — docker.sock 마운트 전제)
        stage('Build Jar') {
            steps {
                script {
                    docker.image('eclipse-temurin:21-jdk-jammy').inside('-v gradle-cache:/root/.gradle') {
                        sh 'chmod +x gradlew && ./gradlew build -x test --no-daemon'
                    }
                }
            }
        }

        stage('Docker Build') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -t ${IMAGE_NAME}:latest ."
            }
        }

        stage('Docker Push') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: "${REGISTRY_CRED}",
                    usernameVariable: 'REGISTRY_USER',
                    passwordVariable: 'REGISTRY_PASS'
                )]) {
                    sh '''
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
                // 서버에 이미 배치된 docker-compose.yml을 재기동 — 레포에는 없음
                sh '''
                    docker compose -f "$COMPOSE_FILE" pull
                    docker compose -f "$COMPOSE_FILE" up -d
                    docker image prune -f
                '''
            }
        }
    }

    post {
        always {
            sh "docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true"
        }
        success {
            echo "배포 완료: ${IMAGE_NAME}:${IMAGE_TAG}"
        }
        failure {
            echo '빌드 또는 배포 실패'
        }
    }
}
