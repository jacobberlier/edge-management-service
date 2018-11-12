node {

    def DEVELOP=false
    def MASTER=false
    if (env.BUILD_TAG==~ /(?s).*develop.*/) {
        DEVELOP=true
    }
    if (env.BUILD_TAG==~ /(?s).*master.*/) {
        MASTER=true
    }

     stage "SCM Checkout"
     checkout scm


   // stage "Coverity"
   // if (DEVELOP || MASTER) {
   //    sh "GB=${env.BRANCH_NAME}; " + ' make clean; make coverity GIT_BRANCH=$(echo ${GB} | tr "/" "_"); make coverity-clean'
   //}

     stage "Clean Existing Images"
     sh '''
         make clean
     '''

     stage "Build"
     sh '''
         make build
     '''

     stage "Image"
     sh '''
         make image
     '''

     stage "Test"
     sh '''
         make test
     '''

     stage "Scan"
     sh '''
         make scan
     '''

    // Upload passing develop images to Artifactory
    // Uploaded images from the last 2 days will be kept
    if (DEVELOP) {
        stage ("Package"){
            // sh('make all-package')
            sh ('make package')
        }

        stage ("Upload"){
            // sh ('make all-upload')
            sh ('make upload')
        }

        stage ("Artifactory Cleanup"){
            // sh ('make all-artifactory-prune')
            sh ('make artifactory-prune')
        }
    }

     stage "Clean Existing Images"
     sh '''
         make clean
     '''

}
