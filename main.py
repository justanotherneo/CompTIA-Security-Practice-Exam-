from logic import Question  # Adjust based on your file structure
import time

# Main function to run the quiz game
def main():

    # Initialize the Question class
    question_instance = Question("", "", "", "", "")  # Empty params as we are using the 'ask_question' method to set values


    # Game loop to keep asking questions until the user quits
    game_over = False

    #welcome statement and use
    print(r'''\

             _______________        
           /               | 
          /        _____   |
          |        \    |  |        ______                 __  __                 _____                                                                                   
          \         \   |__|      /   __  \             /   ___   \              |     |                                                                                          
            \         \         /    /  \  \          /    /    \__|             |     |                                                       
              \         \      /    /____\  \       /    /                  _____|     |_____                                     
     _____      \        /     |    _________\     |    |                  |                 |                                                  
    |     \     /       /      |   |               |    |                  |_____       _____|                                                     
    |      \___/       /       \    \     ___       \    \      ____             |     |                                                  
    |                 /         \    \___/  /         \   \____/  /              |     |                                                                
     \_______________/           \_________/            \_______/                |_____|                                                                                           


                                Security+ Practice Exam

          by: Vergil 
          YouTube: CRZYCYBR
          Instagram: crzy.cybr
          
          If you are getting any value from this program consider subscribing to my YouTube channel or donating
          to one of the following payment methods:
          
          CashApp: $crzycybr
          PayPal: services@crzycybersecurity.com
          Monero: 483vaWanCJeBTy3EsBs9kwHqpXEzgSTva5cXbdE1o5iSRxXnVkZk1Ud6uq9WSfcU2HdTTPjFAfySR2yxpahvU6dSSrMJA7o
          
          vergil@crzycybersecurity.com

          ''')
    
    
    print('Welcome to my Security+ Practice Exam. There is no set amount of questions. There are 500 unique questions\n'
          'and you can take the quiz unit no new questions remain. You will be prompted with questions 1 by 1. Simple \n'
          'type the letter of your selection and hit enter. To quit and have your test scored, simply type \'quit\' or \'q\'\n'
          'and the program will end and you will be scored. Each question is worth 4 points for a maximum possible \n'
          'score of 2000/2000. Questions do not repeat. Let\'s begin.')
    
    
    print('\n')
    print('\n')




    while not game_over:

        # Ask a question and get the result (True if the user quits)
        game_over = question_instance.ask_question()

        # You can include a small delay for better user experience
        time.sleep(1)

    # Once the user quits, show the final score
    question_instance.score_test()


# Run the main function
if __name__ == "__main__":
    main()
