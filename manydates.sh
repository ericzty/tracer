for i in {1..100}
do 
    echo $(date) >> file
done

cat file
